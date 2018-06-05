defmodule ExWire.RLPx do
  alias ExWire.Handshake

  defdelegate add_ack_data(handshake, ack_data), to: Handshake

  def decode_auth(encoded_auth_msg, static_private_key) do
    with {:ok, auth_msg = %Handshake.Struct.AuthMsgV4{}, <<>>} <-
           Handshake.read_auth_msg(encoded_auth_msg, static_private_key) do
      {:ok, auth_msg}
    end
  end

  def decode_ack(encoded_ack_resp, static_private_key) do
    with {:ok, ack_resp, _other_stuff, <<>>} <-
           Handshake.read_ack_resp(encoded_ack_resp, static_private_key) do
      {:ok, ack_resp}
    end
  end

  def prepare_auth_message(handshake, static_private_key) do
    {auth_msg, _, _} =
      Handshake.build_auth_msg(
        handshake.public_key,
        static_private_key,
        handshake.remote_public_key,
        handshake.init_nonce,
        handshake.ephemeral_key_pair
      )

    auth_msg
    |> Handshake.Struct.AuthMsgV4.serialize()
    |> Handshake.EIP8.wrap_eip_8(
      handshake.remote_public_key,
      handshake.ephemeral_key_pair
    )
  end

  def prepare_ack_response(auth_msg, my_ephemeral_key_pair) do
    auth_msg
    |> build_ack_resp()
    |> Handshake.Struct.AckRespV4.serialize()
    |> Handshake.EIP8.wrap_eip_8(
      auth_msg.remote_public_key,
      my_ephemeral_key_pair
    )
  end

  def derive_shared_secrets(
        handshake,
        encoded_auth_msg,
        encoded_ack_resp
      ) do
    {_public_key, ephemeral_private_key} = handshake.ephemeral_key_pair

    secrets =
      ExWire.Framing.Secrets.derive_secrets(
        handshake.initiator,
        ephemeral_private_key,
        handshake.remote_ephemeral_public_key,
        handshake.resp_nonce,
        handshake.init_nonce,
        encoded_auth_msg,
        encoded_ack_resp
      )

    {:ok, secrets}
  end

  defp build_ack_resp(auth_msg) do
    Handshake.build_ack_resp(
      auth_msg.remote_ephemeral_public_key,
      auth_msg.remote_nonce
    )
  end
end
