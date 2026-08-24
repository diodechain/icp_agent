defmodule ICPAgent.HashTest do
  use ExUnit.Case, async: true

  describe "h/1 with binaries" do
    test "hashes an empty binary" do
      assert ICPAgent.h("") == :crypto.hash(:sha256, "")
    end

    test "hashes a non-empty binary" do
      assert ICPAgent.h("hello") == :crypto.hash(:sha256, "hello")
    end

    test "produces 32-byte sha256 digests" do
      assert byte_size(ICPAgent.h("anything")) == 32
    end

    test "produces distinct hashes for distinct inputs" do
      assert ICPAgent.h("a") != ICPAgent.h("b")
    end
  end

  describe "h/1 with lists" do
    test "hashes an empty list using the empty-binary form" do
      assert ICPAgent.h([]) == :crypto.hash(:sha256, "")
    end

    test "hashes a list by joining per-element hashes" do
      list = ["a", "b", "c"]
      expected = :crypto.hash(:sha256, Enum.map_join(list, &ICPAgent.h/1))
      assert ICPAgent.h(list) == expected
    end

    test "order of elements affects the hash" do
      assert ICPAgent.h(["a", "b"]) != ICPAgent.h(["b", "a"])
    end
  end

  describe "h/1 with integers" do
    test "encodes the integer via LEB128 before hashing" do
      assert ICPAgent.h(0) == ICPAgent.h(<<0::8>>)
    end

    test "encodes larger integers via LEB128" do
      # 1689570400000000000 is the canonical LEB128 encoded reference from the
      # existing test in icp_agent_test.exs
      assert ICPAgent.h(1_685_570_400_000_000_000) ==
               :crypto.hash(:sha256, LEB128.encode_unsigned(1_685_570_400_000_000_000))
    end

    test "encodes small integers as single LEB128 bytes" do
      assert ICPAgent.h(1) == :crypto.hash(:sha256, <<1>>)
      assert ICPAgent.h(127) == :crypto.hash(:sha256, <<127>>)
    end

    test "handles integers requiring multi-byte LEB128 encoding" do
      assert ICPAgent.h(128) == :crypto.hash(:sha256, <<128, 1>>)
    end
  end

  describe "h/1 with CBOR tags" do
    test "unwraps a CBOR :bytes tag before hashing" do
      data = "payload"
      assert ICPAgent.h(%CBOR.Tag{tag: :bytes, value: data}) == ICPAgent.h(data)
    end

    test "different tag bodies produce different hashes" do
      assert ICPAgent.h(%CBOR.Tag{tag: :bytes, value: "a"}) !=
               ICPAgent.h(%CBOR.Tag{tag: :bytes, value: "b"})
    end
  end

  describe "h/1 with utf8 tuples" do
    test "unwraps the :utf8 tuple before hashing" do
      assert ICPAgent.h({:utf8, "hello"}) == ICPAgent.h("hello")
    end

    test "different utf8 values produce different hashes" do
      assert ICPAgent.h({:utf8, "a"}) != ICPAgent.h({:utf8, "b"})
    end
  end

  describe "hash_of_map/1" do
    test "hashes an empty map as a single sha256 of the empty string" do
      assert ICPAgent.hash_of_map(%{}) == :crypto.hash(:sha256, "")
    end

    test "is order-independent (sorts by per-key hash)" do
      m1 = %{"a" => 1, "b" => 2}
      m2 = %{"b" => 2, "a" => 1}
      assert ICPAgent.hash_of_map(m1) == ICPAgent.hash_of_map(m2)
    end

    test "matches the documented reference vector" do
      reference =
        ICPAgent.hash_of_map(%{
          "request_type" => "call",
          "sender" => <<0x04>>,
          "ingress_expiry" => 1_685_570_400_000_000_000,
          "canister_id" => "\x00\x00\x00\x00\x00\x00\x04\xD2",
          "method_name" => "hello",
          "arg" => "DIDL\x00\xFD*"
        })

      assert reference |> DiodeClient.Base16.encode() ==
               "0x1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101"
    end

    test "different maps produce different hashes" do
      assert ICPAgent.hash_of_map(%{"a" => 1}) != ICPAgent.hash_of_map(%{"a" => 2})
      assert ICPAgent.hash_of_map(%{"a" => 1}) != ICPAgent.hash_of_map(%{"b" => 1})
    end
  end
end
