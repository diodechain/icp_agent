defmodule ICPAgent do
  @moduledoc """
  This module provides a client for the ICP protocol.

  ## Query example

  This examples uses the `get_latest_sns_version_pretty` method from the SNS-wasm system canister. It's a publicly available method, so no authentication is needed. We're generating a new wallet ad-hoc and using it to query the
  canister.

  ```elixir
  > [versions] = ICPAgent.query("qaa6y-5yaaa-aaaaa-aaafa-cai", DiodeClient.Wallet.new(), "get_latest_sns_version_pretty")
  [
    [
      {"Ledger Index",
      "2adc74fe5667f26ea4c4006309d99b1dfa71787aa43a5c168cb08ec725677996"},
      {"Governance",
      "bd936ef6bb878df87856a0b0c46034a242a88b7f1eeff5439daf6278febca6b7"},
      {"Ledger Archive",
      "f94cf1db965b7042197e5894fef54f5f413bb2ebc607ff0fb59c9d4dfd3babea"},
      {"Swap", "8313ac22d2ef0a0c1290a85b47f235cfa24ca2c96d095b8dbed5502483b9cd18"},
      {"Root", "431cb333feb3f762f742b0dea58745633a2a2ca41075e9933183d850b4ddb259"},
      {"Ledger",
      "25071c2c55ad4571293e00d8e277f442aec7aed88109743ac52df3125209ff45"}
    ]
  ]
  ```

  ## Call example

  Calls and queries both support providing arguments and types in Candid format specification. These are some examples of call structures to give a better understanding of how the types are specified.


  ```elixir
  # Call with passing two blobs as an argument
  > [{cycles, 200}] = ICPAgent.call(canister_id, wallet, "test_blob_input", [:blob, :blob], [blob_a, blob_b])

  # Call with passing a record as an argument
  > [{cycles, 3}] = ICPAgent.call(canister_id, wallet, "test_record_input", [{:record, [{0, :nat32}, {1, :nat32}]}], [{1, 2}])

  # Call with passing a vector of records as an argument
  > {[cycles, 200]} = ICPAgent.call(canister_id, wallet, "test_vec_input", [{:vec, {:record, [{0, :blob}, {1, :blob}]}}], [[{blob_a, blob_b}]])
  ```

  ## Limits

  - Only secp256k1 keys are supported.
  - Did files are not supported and instead types for a call/query must be manually specified.
  """
  alias DiodeClient.Wallet

  def default_canister_id do
    "bkyz2-fmaaa-aaaaa-qaaaq-cai"
  end

  def default_host do
    # "http://127.0.0.1:4943"
    "https://ic0.app"
  end

  def host do
    System.get_env("ICP_DOMAIN", default_host())
  end

  def status do
    curl("#{host()}/api/v2/status", %{}, :get)
  end

  def domain_separator(name) do
    <<byte_size(name), name::binary>>
  end

  # 5 minutes in nanoseconds
  # icp accepts up to 5 minutes ingress expiry into the future.
  # we use 2.5 minutes to account for network latency and clock drift placing it in the middle of the range.
  @ingress_expiry_delta :timer.minutes(2.5) * 1_000_000

  defp sign_query(wallet, query) do
    query =
      Map.merge(query, %{
        "ingress_expiry" => trunc(System.os_time(:nanosecond) + @ingress_expiry_delta),
        "sender" => cbor_bytes(wallet_id(wallet))
      })

    request_id = hash_of_map(query)
    sig = wallet_sign(wallet, domain_separator("ic-request") <> request_id)

    {request_id,
     %{
       "content" => utf8_to_list(query),
       "sender_pubkey" => cbor_bytes(wallet_der(wallet)),
       "sender_sig" => cbor_bytes(sig)
     }}
  end

  def utf8_to_list(map) when is_map(map) and not is_struct(map) do
    Enum.map(map, fn {key, value} -> {key, utf8_to_list(value)} end) |> Map.new()
  end

  def utf8_to_list(list) when is_list(list) do
    Enum.map(list, &utf8_to_list/1)
  end

  def utf8_to_list({:utf8, binary}) when is_binary(binary), do: binary
  def utf8_to_list(other), do: other

  def call(canister_id, wallet, method, types \\ [], args \\ []) do
    {request_id, query} =
      sign_query(wallet, %{
        "request_type" => "call",
        "canister_id" => cbor_bytes(decode_textual(canister_id)),
        "method_name" => method,
        "arg" => cbor_bytes(Candid.encode_parameters(types, args))
      })

    curl("#{host()}/api/v3/canister/#{canister_id}/call", query)
    |> case do
      ret = {:error, _err} ->
        ret

      ret = %{"status" => "replied"} ->
        # read_state(canister_id, wallet, [["request_status", cbor_bytes(request_id), "reply"]])
        value = cbor_decode!(ret["certificate"].value).value
        tree = flatten_tree(value["tree"])

        reply = tree["request_status"][request_id]["reply"]

        if reply != nil do
          {decoded, ""} = Candid.decode_parameters(reply)
          decoded
        else
          tree
        end

      ret ->
        ret
    end
  end

  defp flatten_tree(tree) do
    do_flatten_tree(tree)
    |> List.wrap()
    |> mapify()
  end

  defp mapify(list) when is_list(list) do
    Enum.map(list, fn {key, value} -> {key, mapify(value)} end) |> Map.new()
  end

  defp mapify({key, value}), do: %{key => mapify(value)}
  defp mapify(other), do: other

  defp do_flatten_tree([1 | list]),
    do: Enum.map(list, &do_flatten_tree/1) |> Enum.reject(&is_nil/1) |> List.flatten()

  defp do_flatten_tree([2, key, values]), do: {key.value, do_flatten_tree(values)}
  defp do_flatten_tree([3, value]), do: value.value
  defp do_flatten_tree([4, _sig]), do: nil

  @doc """
  This function queries a canister using the ICP query protocol.

  # Example:

  ```elixir
  > [versions] = ICPAgent.query("qaa6y-5yaaa-aaaaa-aaafa-cai", DiodeClient.Wallet.new(), "get_latest_sns_version_pretty")
  ```
  """
  def query(canister_id, wallet, method, types \\ [], args \\ []) do
    {_request_id, query} =
      sign_query(wallet, %{
        "request_type" => "query",
        "canister_id" => cbor_bytes(decode_textual(canister_id)),
        "method_name" => method,
        "arg" => cbor_bytes(Candid.encode_parameters(types, args))
      })

    curl("#{host()}/api/v2/canister/#{canister_id}/query", query)
    |> case do
      %{"reply" => %{"arg" => ret}} ->
        {ret, ""} = Candid.decode_parameters(ret.value)
        ret

      err = {:error, _error} ->
        err
    end
  end

  def read_state(canister_id, wallet, paths) do
    {_request_id, query} =
      sign_query(wallet, %{
        "request_type" => "read_state",
        "paths" => paths
      })

    %{"reply" => %{"arg" => ret}} =
      curl("#{host()}/api/v2/canister/#{canister_id}/read_state", query)

    {ret, ""} = Candid.decode_parameters(ret.value)
    ret
  end

  defp cbor_decode!(payload, metadata \\ nil) do
    case CBOR.decode(payload) do
      {:ok, decoded, ""} -> decoded
      other -> raise "Failed to decode CBOR: #{inspect({other, metadata})}}"
    end
  end

  defp curl(host, opayload, method \\ :post, headers \\ []) do
    now = System.os_time(:millisecond)
    payload = CBOR.encode(opayload)
    cbor_decode!(payload)
    timeout = 15_000

    opts =
      [
        url: host,
        method: method,
        receive_timeout: timeout,
        connect_options: [timeout: timeout],
        headers: [content_type: "application/cbor"] ++ headers
      ]

    case method do
      :get -> Req.new(opts)
      :post -> Req.new([body: payload] ++ opts)
    end
    |> Req.request()
    |> process_response(now, opayload["content"]["method_name"] || "", payload, host)
  end

  defp process_response({:ok, ret}, now, method, payload, host) do
    p1 = System.os_time(:millisecond)

    if print_requests?() do
      IO.puts(
        "POST #{method} #{String.replace_prefix(host, host(), "")} (#{byte_size(payload)} bytes request)"
      )

      # if method == :post do
      #   IO.puts(">> #{inspect(opayload)}")
      # end
    end

    p2 = System.os_time(:millisecond)

    if print_requests?() do
      IO.puts(
        "POST latency: #{p2 - now}ms http: #{p1 - now}ms (#{byte_size(ret.body)} bytes response)"
      )

      IO.puts("")
    end

    if ret.status >= 300 or ret.status < 200 or String.starts_with?(ret.body, "error:") or
         ret.headers["content-type"] == ["text/plain; charset=utf-8"] do
      {:error, ret.body}
    else
      cbor_decode!(ret.body, ret).value
    end
  end

  defp process_response(other, _now, _method, _payload, _host) do
    other
  end

  def print_requests? do
    System.get_env("ICP_PRINT_REQUESTS", "false") == "true"
  end

  @doc """
  Implementation of the ICP hash function. It is in the ICP docs usually referred to as `H()`.

  https://internetcomputer.org/docs/current/references/ic-interface-spec
  """
  def h([]), do: :crypto.hash(:sha256, "")
  def h(list) when is_list(list), do: :crypto.hash(:sha256, Enum.map_join(list, &h/1))
  def h(number) when is_integer(number), do: h(LEB128.encode_unsigned(number))
  def h(%CBOR.Tag{tag: :bytes, value: data}), do: h(data)
  def h({:utf8, data}) when is_binary(data), do: h(data)
  def h(data) when is_binary(data), do: :crypto.hash(:sha256, data)

  @doc """
  Implementation of the ICP hash function for a map. It is in the ICP docs usually referred to as `hash_of_map`.

  https://internetcomputer.org/docs/current/references/ic-interface-spec#request-id
  """
  def hash_of_map(map) do
    map
    |> Enum.map(fn {key, value} ->
      h(key) <> h(value)
    end)
    |> Enum.sort()
    |> Enum.join("")
    |> h()
  end

  @doc """
  This function converts a DiodeClient.Wallet.t() into a binary representation of the public ICP Principal identifier.

  https://internetcomputer.org/docs/current/references/ic-interface-spec#id-classes
  """
  def wallet_id(wallet) do
    :crypto.hash(:sha224, wallet_der(wallet)) <> <<2>>
  end

  @doc """
  This function computes the CRC32 checksum of a binary.
  """
  def crc32(data) do
    <<:erlang.crc32(data)::size(32)>>
  end

  @doc """
  This function converts a DiodeClient.Wallet.t() into a textual representation of the public ICP Principal identifier.
  """
  def wallet_textual(wallet) do
    wallet_id(wallet)
    |> encode_textual()
  end

  def encode_textual(id) do
    Base.encode32(crc32(id) <> id, case: :lower, padding: false)
    |> String.to_charlist()
    |> Enum.chunk_every(5)
    |> Enum.join("-")
  end

  @doc """
  This function signs a binary with a DiodeClient.Wallet.t() using the secp256k1 algorithm and the ICP signing scheme.
  """
  def wallet_sign(wallet, data) do
    <<_recovery, rest::binary>> = DiodeClient.Secp256k1.sign(Wallet.privkey!(wallet), data, :sha)
    rest
  end

  @doc """
  This function converts a DiodeClient.Wallet.t() into a DER encoded binary representation of the public key.

  The DER encoded binary representation is the canonical form as used by the ICP in various protocol interactions.
  """
  def wallet_der(wallet) do
    public = Wallet.pubkey_long!(wallet)

    term =
      {:OTPSubjectPublicKeyInfo,
       {:PublicKeyAlgorithm, {1, 2, 840, 10_045, 2, 1}, {:namedCurve, {1, 3, 132, 0, 10}}},
       public}

    :public_key.pkix_encode(:OTPSubjectPublicKeyInfo, term, :otp)
  end

  def wallet_private_pem(wallet) do
    privkey = Wallet.privkey!(wallet)
    pubkey = Wallet.pubkey_long!(wallet)

    der =
      :public_key.der_encode(
        :ECPrivateKey,
        {:ECPrivateKey, 1, privkey, {:namedCurve, {1, 3, 132, 0, 10}}, pubkey, :asn1_NOVALUE}
      )

    :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
  end

  @doc """
  This function converts a PEM encoded binary representation of a Secp256k1 curve private key into a DiodeClient.Wallet.t().
  """
  def wallet_from_pem(pem) do
    [{:ECPrivateKey, der, _}] = :public_key.pem_decode(pem)

    {:ECPrivateKey, 1, privkey, {:namedCurve, {1, 3, 132, 0, 10}}, pubkey, :asn1_NOVALUE} =
      :public_key.der_decode(:ECPrivateKey, der)

    wallet = Wallet.from_privkey(privkey)
    ^pubkey = Wallet.pubkey_long!(wallet)
    wallet
  end

  defp cbor_bytes(data) do
    %CBOR.Tag{tag: :bytes, value: data}
  end

  @doc """
  This function decodes a textual representation of an ICP Principal identifier into a binary representation.

  # Example
  ```
  iex> ICPAgent.decode_textual("bkyz2-fmaaa-aaaaa-qaaaq-cai")
  <<128, 0, 0, 0, 0, 16, 0, 1, 1, 1>>
  ```
  """
  def decode_textual(canister_id) do
    <<_crc32::binary-size(4), canister_bin_id::binary>> =
      String.replace(canister_id, "-", "") |> Base.decode32!(case: :lower, padding: false)

    canister_bin_id
  end
end
