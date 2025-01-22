# Elixir ICP Agent for the Internet Computer

The ICP Agent library supports both queries and calls to the Internet Computer. All authentication is done using Secp256k1 keys handled by the `DiodeClient.Wallet` struct.

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
# Generating a new private key as identity
> wallet = DiodeClient.Wallet.new()

# Call with passing two blobs as an argument
> [200] = ICPAgent.call(canister_id, wallet, "test_blob_input", [:blob, :blob], ["blob_a", "blob_b"])

# Call with passing a record as an argument
> [3] = ICPAgent.call(canister_id, wallet, "test_record_input", [{:record, {:nat32, :nat32}}], [{1, 2}])

# Call with passing a record with named fields as an argument
> [3] = ICPAgent.call(canister_id, wallet, "test_named_record_input", [{:record, %{a: :nat32, b: :nat32}}], [{a: 1, b: 2}])

# Call with passing a vector of records as an argument
> [200] = ICPAgent.call(canister_id, wallet, "test_vec_input", [{:vec, {:record, {:blob, :blob}}}], [[{"blob_a", "blob_b"}]])
```

## Limits

- Only secp256k1 keys are supported.
- Did files are not supported and instead types for a call/query must be manually specified.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `icp_agent` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:icp_agent, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/icp_agent>.

