defmodule ICPAgent.TestSupport.NetworkHelpers do
  @moduledoc """
  Helpers for building CBOR-encoded ICP responses and registering Req.Test
  stubs that exercise the ICPAgent network layer.
  """

  @doc """
  Build a CBOR-encoded ICP certificate body whose `request_status` subtree
  carries the given `entries`.

  The `entries` keyword list maps a request-id binary to a keyword list of
  fields, e.g. `[{"status" => "replied", "reply" => reply_binary}]`.

  The returned value is a binary whose decoded form has shape
  `%CBOR.Tag{tag: 55799, value: %{"tree" => forest}}` ready to be wrapped
  with a CBOR `:bytes` tag for use as `certificate.value`.
  """
  def build_certificate(entries) when is_list(entries) do
    request_status_subtree =
      [1 | Enum.map(entries, fn {request_id, fields} -> build_request_status(request_id, fields) end)]

    # The cert tree is wrapped under "request_status" so the production code
    # can look up entries via `tree["request_status"][request_id]`.
    forest = [
      1,
      [
        2,
        bytes_tag("request_status"),
        request_status_subtree
      ]
    ]

    envelope(%{"tree" => forest})
  end

  @doc """
  Wrap a response `body` in the CBOR self-describing tag (`0xD9D9F7`) used by
  every ICP HTTP response. Returns a CBOR-encoded binary.
  """
  def envelope(body) do
    CBOR.encode(%CBOR.Tag{tag: 55799, value: body})
  end

  defp build_request_status(request_id, fields) do
    children = Enum.map(fields, fn {k, v} -> [2, bytes_tag(to_string(k)), [3, leaf(v)]] end)
    [2, bytes_tag(request_id), [1 | children]]
  end

  # Wrap text values as utf8 tags so the cert tree's leaf reader picks them up
  # for strings, while leaving binaries and other values as-is.
  defp leaf(v) when is_binary(v), do: %CBOR.Tag{tag: :bytes, value: v}

  defp leaf(v) when is_atom(v) and v not in [nil, true, false],
    do: %CBOR.Tag{tag: :utf8, value: Atom.to_string(v)}

  defp leaf(v), do: v

  defp bytes_tag(<<>>), do: %CBOR.Tag{tag: :bytes, value: <<>>}

  defp bytes_tag(value) when is_binary(value),
    do: %CBOR.Tag{tag: :bytes, value: value}

  @doc """
  Convenience for the common "status => replied, reply => arg" entry.
  """
  def replied_entry(request_id, arg_binary) when is_binary(arg_binary) do
    {request_id,
     [
       {"status", "replied"},
       {"reply", arg_binary}
     ]}
  end

  @doc """
  Convenience for the common "status => rejected" entry.
  """
  def rejected_entry(request_id, reject_message) do
    {request_id,
     [
       {"status", "rejected"},
       {"reject_message", reject_message}
     ]}
  end

  @doc """
  Stub the ICPAgent network with the given plug function.

  Registers a Req.Test stub and sets the `Application` env so that
  `request_once/3` will inject the stub plug. Cleans up the env after the
  given function returns.
  """
  def with_stub(name, plug_fn, fun) when is_function(plug_fn, 1) and is_function(fun, 0) do
    Req.Test.stub(name, plug_fn)
    previous = Application.get_env(:icp_agent, :req_plug)
    Application.put_env(:icp_agent, :req_plug, {Req.Test, name})

    try do
      fun.()
    after
      Application.delete_env(:icp_agent, :req_plug)

      if previous != nil,
        do: Application.put_env(:icp_agent, :req_plug, previous),
        else: :ok
    end
  end

  @doc """
  Build a CBOR-encoded query `replied` reply (top-level envelope included)
  with the given Candid arg bytes.
  """
  def query_replied(arg_bytes) when is_binary(arg_bytes) do
    envelope(%{
      "status" => "replied",
      "reply" => %{"arg" => %CBOR.Tag{tag: :bytes, value: arg_bytes}}
    })
  end

  @doc """
  Build a CBOR-encoded query `rejected` reply (top-level envelope included).
  """
  def query_rejected(reject_message) do
    envelope(%{
      "status" => "rejected",
      "reject_message" => reject_message
    })
  end

  @doc """
  Build a CBOR-encoded call `replied` body whose certificate carries the
  given entries. The result is the top-level body (already envelope-wrapped).
  """
  def call_replied(entries) when is_list(entries) do
    cert_body = build_certificate(entries)

    envelope(%{
      "status" => "replied",
      "certificate" => %CBOR.Tag{tag: :bytes, value: cert_body}
    })
  end

  @doc """
  Build a CBOR-encoded `read_state` reply carrying the certificate bytes
  encoded for the given entries.
  """
  def read_state_with_cert(entries) when is_list(entries) do
    cert_body = build_certificate(entries)
    envelope(%{"certificate" => %CBOR.Tag{tag: :bytes, value: cert_body}})
  end

  @doc """
  Send a CBOR-encoded body as a 200 OK reply from the stub.
  """
  def cbor_ok(conn, body) when is_binary(body) do
    conn
    |> Plug.Conn.put_resp_header("content-type", "application/cbor")
    |> Plug.Conn.send_resp(200, body)
  end
end
