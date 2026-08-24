defmodule ICPAgent.NetworkTest do
  # These tests stub the HTTP layer via Req.Test. We intentionally use
  # `async: false` because each test installs and tears down an
  # `Application` env value that drives the stub plug.
  use ExUnit.Case, async: false

  alias DiodeClient.Wallet
  alias ICPAgent.TestSupport.NetworkHelpers

  @canister "tnqzy-zaaaa-aaaao-qkeza-cai"
  @arg <<68, 73, 68, 76, 1, 108, 2, 0, 121, 1, 121, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0>>

  setup do
    # Speed up the poll loop so tests run quickly.
    previous_poll = Application.get_env(:icp_agent, :poll_sleep_ms)
    Application.put_env(:icp_agent, :poll_sleep_ms, 1)
    on_exit(fn ->
      if previous_poll,
        do: Application.put_env(:icp_agent, :poll_sleep_ms, previous_poll),
        else: Application.delete_env(:icp_agent, :poll_sleep_ms)
    end)

    # Disable Req retries for fast tests; the production default of
    # :transient is restored on test exit.
    previous_retry = Application.get_env(:icp_agent, :req_retry)
    Application.put_env(:icp_agent, :req_retry, false)
    on_exit(fn ->
      if previous_retry,
        do: Application.put_env(:icp_agent, :req_retry, previous_retry),
        else: Application.delete_env(:icp_agent, :req_retry)
    end)

    :ok
  end

  # ── status ────────────────────────────────────────────────────────────────

  describe "status/0" do
    test "returns the decoded status body" do
      inner = %{
        "replica_health_status" => "healthy",
        "root_key" => %CBOR.Tag{tag: :bytes, value: <<1, 2, 3, 4>>}
      }

      body = NetworkHelpers.envelope(inner)

      NetworkHelpers.with_stub(:status_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert %{"replica_health_status" => "healthy", "root_key" => root_key} =
                 ICPAgent.status()

        assert %CBOR.Tag{tag: :bytes, value: <<1, 2, 3, 4>>} = root_key
      end)
    end
  end

  # ── query ──────────────────────────────────────────────────────────────────

  describe "query/6" do
    test "returns the decoded reply value" do
      body = NetworkHelpers.query_replied(@arg)

      NetworkHelpers.with_stub(:query_replied_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert [{0, 1}] = ICPAgent.query(@canister, Wallet.new(), "test_record_output")
      end)
    end

    test "accepts a reply without an explicit status (polling path)" do
      body = NetworkHelpers.envelope(%{"reply" => %{"arg" => %CBOR.Tag{tag: :bytes, value: @arg}}})

      NetworkHelpers.with_stub(:query_no_status_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert [{0, 1}] = ICPAgent.query(@canister, Wallet.new(), "test_record_output")
      end)
    end

    test "returns a rejected tuple" do
      body = NetworkHelpers.query_rejected("canister trapped: out of fuel")

      NetworkHelpers.with_stub(:query_rejected_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert {:error, {:rejected, "canister trapped: out of fuel"}} =
                 ICPAgent.query(@canister, Wallet.new(), "test_record_output")
      end)
    end

    test "passes through an :error tuple from the request layer" do
      NetworkHelpers.with_stub(:query_error_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, "error: upstream exploded")
      end, fn ->
        assert {:error, body} = ICPAgent.query(@canister, Wallet.new(), "test_record_output")
        assert body =~ "error: upstream exploded"
      end)
    end

    test "returns {:error, {:unknown_request_status, _}} for unexpected bodies" do
      body = NetworkHelpers.envelope(%{"status" => "weird"})

      NetworkHelpers.with_stub(:query_unknown_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert {:error, {:unknown_request_status, %{"status" => "weird"}}} =
                 ICPAgent.query(@canister, Wallet.new(), "test_record_output")
      end)
    end
  end

  describe "process_call_return catch-all" do
    test "logs an error and returns the unexpected result unchanged" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          body = NetworkHelpers.envelope(%{"weird" => "stuff"})

          NetworkHelpers.with_stub(:catch_all_stub, fn conn ->
            NetworkHelpers.cbor_ok(conn, body)
          end, fn ->
            assert %{"weird" => "stuff"} =
                     ICPAgent.call(@canister, Wallet.new(), "test_record_output")
          end)
        end)

      assert log =~ "ICPAgent: call returned unexpected result"
    end

    test "passes through an unexpected %{...} from process_call_return" do
      # The response is %{status: "processing"} which does not match any
      # explicit clause, so the catch-all branch fires.
      body = NetworkHelpers.envelope(%{"status" => "processing"})

      NetworkHelpers.with_stub(:processing_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert %{"status" => "processing"} =
                 ICPAgent.call(@canister, Wallet.new(), "test_record_output")
      end)
    end
  end

  describe "raw_call/5" do
    test "returns the request_id and the raw fetch result" do
      NetworkHelpers.with_stub(:raw_call_stub, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/cbor")
        |> Plug.Conn.send_resp(202, "")
      end, fn ->
        {request_id, {:ok, :accepted}} =
          ICPAgent.raw_call(@canister, Wallet.new(), "test_record_output", [], [])

        assert is_binary(request_id)
        assert byte_size(request_id) == 32
      end)
    end
  end

  describe "call/7" do
    test "decodes a replied certificate" do
      wallet = Wallet.new()

      NetworkHelpers.with_stub(:call_replied_stub, fn conn ->
        # Echo the request_id back in the certificate so the lookup hits.
        body = read_body(conn)
        {:ok, decoded, ""} = CBOR.decode(body)
        request_id = compute_request_id(decoded)

        reply_body =
          NetworkHelpers.call_replied([NetworkHelpers.replied_entry(request_id, @arg)])

        NetworkHelpers.cbor_ok(conn, reply_body)
      end, fn ->
        assert [{0, 1}] = ICPAgent.call(@canister, wallet, "test_record_output")
      end)
    end

    test "decodes a rejected certificate" do
      wallet = Wallet.new()

      NetworkHelpers.with_stub(:call_rejected_stub, fn conn ->
        body = read_body(conn)
        {:ok, decoded, ""} = CBOR.decode(body)
        request_id = compute_request_id(decoded)

        reply_body =
          NetworkHelpers.call_replied([NetworkHelpers.rejected_entry(request_id, "out of fuel")])

        NetworkHelpers.cbor_ok(conn, reply_body)
      end, fn ->
        assert {:error, {:rejected, "out of fuel"}} =
                 ICPAgent.call(@canister, wallet, "test_record_output")
      end)
    end

    test "returns {:error, {:unknown_request_status, tree}} when the cert tree lacks the request" do
      body = NetworkHelpers.call_replied([])

      NetworkHelpers.with_stub(:call_unknown_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert {:error, {:unknown_request_status, _}} =
                 ICPAgent.call(@canister, Wallet.new(), "test_record_output")
      end)
    end

    test "returns {:error, {:unknown_request_status, other}} for unexpected inner status" do
      request_id = :crypto.strong_rand_bytes(32)
      body = NetworkHelpers.call_replied([{request_id, [{"status", "weird"}]}])

      NetworkHelpers.with_stub(:call_weird_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert {:error, {:unknown_request_status, other}} =
                 ICPAgent.call(@canister, Wallet.new(), "test_record_output")

        assert is_map(other)
      end)
    end

    test "propagates a :error tuple from the fetch layer" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          NetworkHelpers.with_stub(:call_error_stub, fn conn ->
            NetworkHelpers.cbor_ok(conn, "error: upstream busted")
          end, fn ->
            assert {:error, msg} = ICPAgent.call(@canister, Wallet.new(), "test_record_output")
            assert msg =~ "error: upstream busted"
          end)
        end)

      # Errors go through the {:error, _err} clause, not the catch-all,
      # so the log should not contain the "unexpected result" message.
      refute log =~ "ICPAgent: call returned unexpected result"
    end
  end

  # ── read_state ────────────────────────────────────────────────────────────

  describe "read_state/3" do
    test "returns the decoded response for a successful request" do
      body = NetworkHelpers.read_state_with_cert([])

      NetworkHelpers.with_stub(:read_state_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        result = ICPAgent.read_state(@canister, Wallet.new(), [])
        assert %{"certificate" => %CBOR.Tag{tag: :bytes, value: _}} = result
      end)
    end
  end

  # ── process_response error paths ──────────────────────────────────────────

  describe "process_response/5 error paths" do
    test "returns {:error, body} when the response body starts with 'error:'" do
      NetworkHelpers.with_stub(:proc_error_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, "error: upstream busted")
      end, fn ->
        assert {:error, "error: upstream busted"} = ICPAgent.status()
      end)
    end

    test "returns {:error, body} when the response body starts with 'Message did not complete'" do
      NetworkHelpers.with_stub(:proc_msg_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, "Message did not complete: connection closed")
      end, fn ->
        assert {:error, msg} = ICPAgent.status()
        assert msg =~ "Message did not complete"
      end)
    end

    test "returns {:error, body} when the response content-type is text/plain" do
      NetworkHelpers.with_stub(:proc_text_stub, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "text/plain; charset=utf-8")
        |> Plug.Conn.send_resp(200, "some plain text")
      end, fn ->
        assert {:error, "some plain text"} = ICPAgent.status()
      end)
    end

    test "returns {:error, body} for a 500 status response" do
      NetworkHelpers.with_stub(:proc_500_stub, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/cbor")
        |> Plug.Conn.send_resp(500, "internal failure")
      end, fn ->
        assert {:error, "internal failure"} = ICPAgent.status()
      end)
    end

    test "returns {:error, body} for a 400 status response" do
      NetworkHelpers.with_stub(:proc_400_stub, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/cbor")
        |> Plug.Conn.send_resp(400, "bad request")
      end, fn ->
        assert {:error, "bad request"} = ICPAgent.status()
      end)
    end
  end

  # ── fetch_with_fallback on nxdomain ───────────────────────────────────────

  describe "fetch_with_fallback nxdomain retry" do
    test "falls through to the next boundary host when the first returns nxdomain" do
      # Override `ICP_DOMAIN` to a known-bad host so the primary host hits
      # nxdomain and the next boundary host is intercepted by our stub.
      previous = Application.get_env(:icp_agent, :req_plug)
      Req.Test.stub(:nxdomain_fallback, fn conn -> NetworkHelpers.cbor_ok(conn, NetworkHelpers.envelope(%{"ok" => true})) end)

      System.put_env("ICP_DOMAIN", "https://nonexistent.invalid")

      Application.put_env(:icp_agent, :req_plug, {Req.Test, :nxdomain_fallback})

      try do
        assert %{"ok" => true} = ICPAgent.status()
      after
        System.delete_env("ICP_DOMAIN")
        Application.delete_env(:icp_agent, :req_plug)

        if previous != nil,
          do: Application.put_env(:icp_agent, :req_plug, previous),
          else: :ok
      end
    end
  end

  # ── poll_call timeout ─────────────────────────────────────────────────────

  describe "poll_call/5 timeout" do
    test "returns {:error, \"Call timed out\"} when retries exceeds the limit" do
      # Drive poll_call directly with retries > 10 to short-circuit the loop.
      request_id = :crypto.strong_rand_bytes(32)
      assert {:error, "Call timed out"} = ICPAgent.poll_call(@canister, Wallet.new(), request_id, nil, 11)
    end

    test "returns {:error, \"Call timed out\"} when the read_state never returns a certificate" do
      # Return a CBOR response without a "certificate" key so poll_call's
      # pattern match always falls through to the recursion branch.
      body = NetworkHelpers.envelope(%{"no_certificate" => true})

      NetworkHelpers.with_stub(:poll_timeout_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        request_id = :crypto.strong_rand_bytes(32)
        # poll_sleep_ms is set to 1ms in setup, so this test finishes quickly.
        assert {:error, "Call timed out"} = ICPAgent.poll_call(@canister, Wallet.new(), request_id)
      end)
    end

    test "decodes the reply as soon as a certificate is observed" do
      request_id = :crypto.strong_rand_bytes(32)
      body = NetworkHelpers.read_state_with_cert([NetworkHelpers.replied_entry(request_id, @arg)])

      NetworkHelpers.with_stub(:poll_replied_stub, fn conn ->
        NetworkHelpers.cbor_ok(conn, body)
      end, fn ->
        assert [{0, 1}] = ICPAgent.poll_call(@canister, Wallet.new(), request_id)
      end)
    end
  end

  defp read_body(conn) do
    {:ok, body, _conn} = Plug.Conn.read_body(conn, length: 1_000_000_000)
    body
  end

  # Re-derive the request_id from the request body the same way `sign_query/2`
  # does internally so the stub can echo it back in the certificate.
  defp compute_request_id(body) do
    query = body["content"]
    ICPAgent.hash_of_map(query)
  end
end
