defmodule ICPAgent do
  alias DiodeClient.Wallet

  def default_canister_id() do
    "bkyz2-fmaaa-aaaaa-qaaaq-cai"
  end

  def default_host() do
    # "http://127.0.0.1:4943"
    "https://ic0.app"
  end

  def host() do
    System.get_env("ICP_DOMAIN", default_host())
  end

  def status() do
    curl("#{host()}/api/v2/status", %{}, :get)
  end

  def domain_separator(name) do
    <<byte_size(name), name::binary>>
  end

  defp sign_query(wallet, query) do
    query =
      Map.merge(query, %{
        "ingress_expiry" => System.os_time(:nanosecond) + 1000 * 1000 * 1000,
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

    ret = curl("#{host()}/api/v3/canister/#{canister_id}/call", query)

    if ret["status"] == "replied" do
      # read_state(canister_id, wallet, [["request_status", cbor_bytes(request_id), "reply"]])
      {:ok, %{value: value}, ""} = CBOR.decode(ret["certificate"].value)
      tree = flatten_tree(value["tree"])

      reply = tree["request_status"][request_id]["reply"]

      if reply != nil do
        {decoded, ""} = Candid.decode_parameters(reply)
        decoded
      else
        tree
      end
    else
      ret
    end
  end

  defp flatten_tree(tree) do
    do_flatten_tree(tree)
    |> List.wrap()
    |> mapify()
  end

  defp mapify(list) when is_list(list), do: Enum.map(list, &mapify/1) |> Map.new()
  defp mapify({key, value}), do: {key, mapify(value)}
  defp mapify(other), do: other

  defp do_flatten_tree([1 | list]),
    do: Enum.map(list, &do_flatten_tree/1) |> Enum.reject(&is_nil/1) |> List.flatten()

  defp do_flatten_tree([2, key, values]), do: {key.value, do_flatten_tree(values)}
  defp do_flatten_tree([3, value]), do: value.value
  defp do_flatten_tree([4, _sig]), do: nil

  @doc """
  This function queries a canister using the ICP query protocol.
  """
  def query(canister_id, wallet, method, types \\ [], args \\ []) do
    {_request_id, query} =
      sign_query(wallet, %{
        "request_type" => "query",
        "canister_id" => cbor_bytes(decode_textual(canister_id)),
        "method_name" => method,
        "arg" => cbor_bytes(Candid.encode_parameters(types, args))
      })

    %{"reply" => %{"arg" => ret}} = curl("#{host()}/api/v2/canister/#{canister_id}/query", query)

    {ret, ""} = Candid.decode_parameters(ret.value)
    ret
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

  defp curl(host, opayload, method \\ :post, headers \\ []) do
    now = System.os_time(:millisecond)
    payload = CBOR.encode(opayload)
    {:ok, _decoded, ""} = CBOR.decode(payload)

    timeout = 15_000

    opts =
      [
        url: host,
        method: method,
        receive_timeout: timeout,
        connect_options: [timeout: timeout],
        headers: [content_type: "application/cbor"] ++ headers
      ]

    {:ok, ret} =
      case method do
        :get -> Req.new(opts)
        :post -> Req.new([body: payload] ++ opts)
      end
      |> Req.request()

    p1 = System.os_time(:millisecond)

    if print_requests?() do
      method = opayload["content"]["method_name"] || ""

      IO.puts(
        "POST #{method} #{String.replace_prefix(host, host(), "")} (#{byte_size(payload)} bytes request)"
      )

      # if method == :post do
      #   IO.puts(">> #{inspect(opayload)}")
      # end
    end

    {:ok, tag, ""} = CBOR.decode(ret.body)

    p2 = System.os_time(:millisecond)

    if print_requests?() do
      # IO.puts("<< #{inspect(tag.value)}")
      IO.puts(
        "POST latency: #{p2 - now}ms http: #{p1 - now}ms (#{byte_size(ret.body)} bytes response)"
      )

      IO.puts("")
    end

    tag.value
  end

  def print_requests?() do
    :persistent_term.get(:print_requests?, true)
  end

  @doc """
  Implementation of the ICP hash function. It is in the ICP docs usually referred to as `H()`.

  https://internetcomputer.org/docs/current/references/ic-interface-spec
  """
  def h([]), do: :crypto.hash(:sha256, "")
  def h(list) when is_list(list), do: :crypto.hash(:sha256, Enum.join(Enum.map(list, &h/1), ""))
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
    id = wallet_id(wallet)

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
