defmodule ICPAgent.VetKD do
  alias ExEcc.BLS.PointCompression
  alias ExEcc.BLS.Ciphersuites.G2Basic
  alias ExEcc.OptimizedBLS12381.OptimizedCurve, as: Curve

  def new_transport_private_key() do
    rem(:binary.decode_unsigned(:crypto.strong_rand_bytes(64)), Curve.curve_order())
  end

  def transport_private_key_to_public_key(transport_private_key) do
    G2Basic.sk_to_pk(transport_private_key)
  end

  def decrypt_key(encrypted_key, transport_privkey) when is_integer(transport_privkey) do
    # Reference: https://github.com/dfinity/vetkeys/blob/dd255c8fa1ec0356f9448f1728ed4d6a5b736308/frontend/ic_vetkeys/src/utils/utils.ts#L584
    <<c1::unsigned-size(384), c2x::unsigned-size(384), c2y::unsigned-size(384),
      c3::unsigned-size(384)>> = encrypted_key

    c1 = PointCompression.decompress_g1(c1)
    _c2 = PointCompression.decompress_g2({c2x, c2y})
    c3 = PointCompression.decompress_g1(c3)

    c1_tsk = Curve.multiply(c1, transport_privkey)
    Curve.add(c3, Curve.neg(c1_tsk)) |> Curve.normalize()
  end
end
