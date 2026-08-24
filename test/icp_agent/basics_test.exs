defmodule ICPAgent.BasicsTest do
  use ExUnit.Case, async: true

  describe "default_canister_id/0" do
    test "returns the well-known registry canister id" do
      assert ICPAgent.default_canister_id() == "bkyz2-fmaaa-aaaaa-qaaaq-cai"
    end

    test "result is a valid textual canister id that round-trips" do
      id = ICPAgent.default_canister_id()
      assert is_binary(id)
      assert ICPAgent.encode_textual(ICPAgent.decode_textual(id)) == id
    end
  end

  describe "default_host/0" do
    test "returns the default ic0.app host" do
      assert ICPAgent.default_host() == "https://ic0.app"
    end

    test "result is a binary" do
      assert is_binary(ICPAgent.default_host())
    end
  end

  describe "boundary_hosts/0" do
    test "returns the three official boundary hosts" do
      hosts = ICPAgent.boundary_hosts()
      assert "https://ic0.app" in hosts
      assert "https://icp0.io" in hosts
      assert "https://icp-api.io" in hosts
      assert length(hosts) == 3
    end

    test "every entry is a binary URL starting with https://" do
      for host <- ICPAgent.boundary_hosts() do
        assert is_binary(host)
        assert String.starts_with?(host, "https://")
      end
    end
  end

  describe "host/0" do
    test "uses default_host when ICP_DOMAIN env var is unset" do
      System.delete_env("ICP_DOMAIN")
      assert ICPAgent.host() == ICPAgent.default_host()
    end

    test "uses ICP_DOMAIN env var when set" do
      System.put_env("ICP_DOMAIN", "https://custom.example.com")
      try do
        assert ICPAgent.host() == "https://custom.example.com"
      after
        System.delete_env("ICP_DOMAIN")
      end
    end

    test "strips a trailing slash from ICP_DOMAIN" do
      System.put_env("ICP_DOMAIN", "https://custom.example.com/")
      try do
        assert ICPAgent.host() == "https://custom.example.com"
      after
        System.delete_env("ICP_DOMAIN")
      end
    end

    test "preserves a trailing path component" do
      System.put_env("ICP_DOMAIN", "https://example.com/path/")
      try do
        assert ICPAgent.host() == "https://example.com/path"
      after
        System.delete_env("ICP_DOMAIN")
      end
    end
  end

  describe "domain_separator/1" do
    test "prefixes the byte-length of the name" do
      assert ICPAgent.domain_separator("ic-request") == <<10, "ic-request"::binary>>
      assert ICPAgent.domain_separator("") == <<0>>
      assert ICPAgent.domain_separator("a") == <<1, "a"::binary>>
    end

    test "produces distinct separators for different names" do
      assert ICPAgent.domain_separator("foo") != ICPAgent.domain_separator("bar")
    end

    test "produces distinct separators for names with same prefix" do
      assert ICPAgent.domain_separator("ab") != ICPAgent.domain_separator("abc")
    end
  end

  describe "print_requests?/0" do
    test "defaults to false when env var is unset" do
      System.delete_env("ICP_PRINT_REQUESTS")
      assert ICPAgent.print_requests?() == false
    end

    test "returns true when ICP_PRINT_REQUESTS is 'true'" do
      System.put_env("ICP_PRINT_REQUESTS", "true")
      try do
        assert ICPAgent.print_requests?() == true
      after
        System.delete_env("ICP_PRINT_REQUESTS")
      end
    end

    test "returns false for any other value" do
      System.put_env("ICP_PRINT_REQUESTS", "yes")
      try do
        assert ICPAgent.print_requests?() == false
      after
        System.delete_env("ICP_PRINT_REQUESTS")
      end
    end
  end
end
