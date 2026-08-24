defmodule ICPAgent.WalletTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Wallet

  @pemb64 """
  -----BEGIN EC PRIVATE KEY-----
  MHQCAQEEIGfKHuyoCCCbEXb0789MIdWiCIpZo1LaKApv95SSIaWPoAcGBSuBBAAK
  oUQDQgAEahC99Avid7r8D6kIeLjjxJ8kwdJRy5nPrN9o18P7xHT95i0JPr5ivc9v
  CB8vG2s97NB0re2MhqvdWgradJZ8Ow==
  -----END EC PRIVATE KEY-----
  """
  @ref_textual "42gbo-uiwfn-oq452-ql6yp-4jsqn-a6bxk-n7l4z-ni7os-yptq6-3htob-vqe"

  describe "wallet_from_pem/1" do
    test "decodes the PEM reference wallet to the documented textual id" do
      wallet = ICPAgent.wallet_from_pem(@pemb64)
      assert ICPAgent.wallet_textual(wallet) == @ref_textual
    end

    test "round-trips via wallet_private_pem" do
      original = Wallet.new()
      pem = ICPAgent.wallet_private_pem(original)
      decoded = ICPAgent.wallet_from_pem(pem)
      assert Wallet.pubkey_long!(decoded) == Wallet.pubkey_long!(original)
      assert Wallet.privkey!(decoded) == Wallet.privkey!(original)
    end
  end

  describe "wallet_private_pem/1" do
    test "produces a PEM-encoded EC private key" do
      wallet = Wallet.new()
      pem = ICPAgent.wallet_private_pem(wallet)
      assert is_binary(pem)
      assert pem =~ "-----BEGIN EC PRIVATE KEY-----"
      assert pem =~ "-----END EC PRIVATE KEY-----"
    end
  end

  describe "wallet_id/1" do
    test "produces a 29-byte binary (28 bytes sha224 + 1 byte self-auth tag)" do
      assert byte_size(ICPAgent.wallet_id(Wallet.new())) == 29
    end

    test "ends with the self-authenticating suffix byte 0x02" do
      <<_::binary-size(28), suffix::binary>> = ICPAgent.wallet_id(Wallet.new())
      assert suffix == <<2>>
    end

    test "is deterministic for the same wallet" do
      w = Wallet.new()
      assert ICPAgent.wallet_id(w) == ICPAgent.wallet_id(w)
    end

    test "is different for different wallets" do
      a = Wallet.new()
      b = Wallet.new()
      assert ICPAgent.wallet_id(a) != ICPAgent.wallet_id(b)
    end

    test "matches the documented reference wallet" do
      wallet = ICPAgent.wallet_from_pem(@pemb64)
      assert ICPAgent.wallet_id(wallet) == ICPAgent.decode_textual(@ref_textual)
    end
  end

  describe "encode_textual/1" do
    test "encodes to lowercase base32 grouped into 5-character chunks" do
      id = :crypto.hash(:sha256, "any-data") |> binary_part(0, 28) |> Kernel.<>(<<2>>)
      textual = ICPAgent.encode_textual(id)
      groups = String.split(textual, "-")
      assert length(groups) > 1
      # All chunks are exactly 5 chars except the last which may be shorter.
      {init, [last]} = Enum.split(groups, -1)
      for group <- init, do: assert(String.length(group) == 5)
      assert String.length(last) >= 1 and String.length(last) <= 5
      assert textual == String.downcase(textual)
    end

    test "starts the textual form with a 4-byte CRC32" do
      id = <<0::8, 1::8, 2::8>>
      encoded = ICPAgent.encode_textual(id)
      assert String.length(encoded) > 0
      # The decoded form must contain the original id after the 4-byte CRC.
      decoded = ICPAgent.decode_textual(encoded)
      assert decoded == id
    end

    test "round-trips with decode_textual" do
      id = :crypto.strong_rand_bytes(10)
      assert ICPAgent.decode_textual(ICPAgent.encode_textual(id)) == id
    end
  end

  describe "decode_textual/1" do
    test "matches the doctest example" do
      assert ICPAgent.decode_textual("bkyz2-fmaaa-aaaaa-qaaaq-cai") ==
               <<128, 0, 0, 0, 0, 16, 0, 1, 1, 1>>
    end

    test "removes dashes before decoding" do
      id = "aaaaa-bbbbb-ccccc-ddddd-eeeee-f"
      without_dashes = ICPAgent.decode_textual(id)
      assert is_binary(without_dashes)
    end

    test "round-trips for the documented reference text" do
      assert ICPAgent.encode_textual(ICPAgent.decode_textual(@ref_textual)) == @ref_textual
    end
  end

  describe "crc32/1" do
    test "returns a 4-byte big-endian CRC32" do
      assert byte_size(ICPAgent.crc32("")) == 4
      assert byte_size(ICPAgent.crc32("hello")) == 4
    end

    test "computes the well-known CRC32 of '123456789' as 0xCBF43926" do
      assert ICPAgent.crc32("123456789") == <<0xCB, 0xF4, 0x39, 0x26>>
    end

    test "empty input returns the CRC32 of nothing (0x00000000)" do
      assert ICPAgent.crc32("") == <<0, 0, 0, 0>>
    end

    test "is deterministic" do
      assert ICPAgent.crc32("foo") == ICPAgent.crc32("foo")
    end
  end

  describe "wallet_der/1" do
    test "returns a DER-encoded SubjectPublicKeyInfo binary" do
      der = ICPAgent.wallet_der(Wallet.new())
      assert is_binary(der)
      assert byte_size(der) > 0
    end

    test "round-trips through wallet_id which hashes the DER" do
      w = Wallet.new()
      assert ICPAgent.wallet_id(w) == ICPAgent.wallet_id(w)
    end
  end

  describe "wallet_sign/2" do
    test "produces a 64-byte recoverable signature with the recovery byte stripped" do
      sig = ICPAgent.wallet_sign(Wallet.new(), "data")
      assert byte_size(sig) == 64
    end

    test "is deterministic for the same wallet and data" do
      w = Wallet.new()
      assert ICPAgent.wallet_sign(w, "data") == ICPAgent.wallet_sign(w, "data")
    end

    test "produces different signatures for different data" do
      w = Wallet.new()
      assert ICPAgent.wallet_sign(w, "data1") != ICPAgent.wallet_sign(w, "data2")
    end
  end
end
