defmodule ICPAgentTest do
  alias DiodeClient.Wallet
  use ExUnit.Case
  doctest ICPAgent

  test "greets the world" do
    {decoded, ""} =
      <<68, 73, 68, 76, 1, 107, 2, 156, 194, 1, 127, 229, 142, 180, 2, 113, 1, 0, 0>>
      |> Candid.decode_parameters()

    ^decoded = [{Candid.namehash("ok"), nil}]

    {[{0, 1}], ""} =
      <<68, 73, 68, 76, 1, 108, 2, 0, 121, 1, 121, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0>>
      |> Candid.decode_parameters()

    wallet =
      ICPAgent.wallet_from_pem("""
      -----BEGIN EC PRIVATE KEY-----
      MHQCAQEEIGfKHuyoCCCbEXb0789MIdWiCIpZo1LaKApv95SSIaWPoAcGBSuBBAAK
      oUQDQgAEahC99Avid7r8D6kIeLjjxJ8kwdJRy5nPrN9o18P7xHT95i0JPr5ivc9v
      CB8vG2s97NB0re2MhqvdWgradJZ8Ow==
      -----END EC PRIVATE KEY-----
      """)

    reftext = "42gbo-uiwfn-oq452-ql6yp-4jsqn-a6bxk-n7l4z-ni7os-yptq6-3htob-vqe"
    refbin = ICPAgent.decode_textual(reftext)

    idsize = byte_size(ICPAgent.wallet_id(wallet))
    ^idsize = byte_size(refbin)
    ^refbin = ICPAgent.wallet_id(wallet)
    ^reftext = ICPAgent.wallet_textual(wallet)
    IO.puts("wallet textual: #{reftext}")

    "0xdb8e57abc8cda1525d45fdd2637af091bc1f28b35819a40df71517d1501f2c76" =
      ICPAgent.h(1_685_570_400_000_000_000) |> DiodeClient.Base16.encode()

    "0x6c0b2ae49718f6995c02ac5700c9c789d7b7862a0d53e6d40a73f1fcd2f70189" =
      ICPAgent.h("DIDL\x00\xFD*") |> DiodeClient.Base16.encode()

    "0x1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101" =
      ICPAgent.hash_of_map(%{
        "request_type" => "call",
        "sender" => <<0x04>>,
        "ingress_expiry" => 1_685_570_400_000_000_000,
        "canister_id" => "\x00\x00\x00\x00\x00\x00\x04\xD2",
        "method_name" => "hello",
        "arg" => "DIDL\x00\xFD*"
      })
      |> DiodeClient.Base16.encode()

    w =
      Wallet.from_privkey(
        DiodeClient.Base16.decode(
          "0xb6dbce9418872c4b8f5a10a5778e247c60cdb0265f222c0bfdbe565cfe63d64a"
        )
      )

    IO.puts("wallet_textual: #{ICPAgent.wallet_textual(w)}")
    IO.puts("wallet_address: #{Wallet.printable(w)}")

    # canister_id = default_canister_id()

    # [{0, 1}] = call(canister_id, w, "test_record_output", [], [])

    # [3] =
    #   call(canister_id, w, "test_record_input", [{:record, [{0, :nat32}, {1, :nat32}]}], [{1, 2}])

    # identity_contract = DiodeClient.Base16.decode("0x08ff68fe9da498223d4fc953bc4c336ec5726fec")
    # [200] = call(canister_id, w, "update_identity_role", [:blob, :blob], [Wallet.pubkey_long!(w), identity_contract])
    # # test_batch_write(w, canister_id)

    # [n] = query(canister_id, w, "get_max_message_id")

    # message = "hello diode #{n}"
    # key_id = Wallet.address!(w)
    # isOk(call(canister_id, w, "add_message", [:blob, :blob], [key_id, message]))
    # n2 = n + 1
    # [^n2] = query(canister_id, w, "get_max_message_id")

    # message = "hello diode #{n2}"
    # key_id = Wallet.address!(w)
    # isOk(call(canister_id, w, "add_message", [:blob, :blob], [key_id, message]))
    # n3 = n2 + 1
    # [^n3] = query(canister_id, w, "get_max_message_id")
  end

  test "status" do
    %{"replica_health_status" => "healthy", "root_key" => root_key} =
      ICPAgent.status()

    IO.puts("root_key: #{inspect(Base.encode16(root_key.value))}")

    assert Base.encode16(root_key.value) ==
             "308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C05030201036100814C0E6EC71FAB583B08BD81373C255C3C371B2E84863C98A4F1E08B74235D14FB5D9C0CD546D9685F913A0C0B2CC5341583BF4B4392E467DB96D65B9BB4CB717112F8472E0D5A4D14505FFD7484B01291091C5F87B98883463F98091A0BAAAE"
  end

  test "query sns" do
    # https://internetcomputer.org/docs/current/developer-docs/smart-contracts/advanced-features/system-canisters
    address = "qaa6y-5yaaa-aaaaa-aaafa-cai"
    # https://github.com/dfinity/ic/blob/master/rs/nns/sns-wasm/canister/sns-wasm.did
    method = "get_latest_sns_version_pretty"
    [version] = ICPAgent.query(address, Wallet.new(), method)
  end

  test "pem" do
    w = Wallet.new()
    assert ICPAgent.wallet_from_pem(ICPAgent.wallet_private_pem(w)) == w
  end
end
