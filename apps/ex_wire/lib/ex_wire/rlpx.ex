defmodule ExWire.RLPx do
  alias ExWire.Handshake

  def handle_auth_received(
        encoded_auth_msg,
        my_ephemeral_key_pair,
        my_nonce,
        my_static_private_key
      ) do
    with {:ok, auth_msg} <- decode_auth(encoded_auth_msg, my_static_private_key),
         {:ok, encoded_ack_resp} <- prepare_ack_response(auth_msg, my_ephemeral_key_pair),
         {:ok, secrets} <-
           derive_shared_secrets(
             auth_msg,
             encoded_auth_msg,
             encoded_ack_resp,
             my_ephemeral_key_pair,
             my_nonce
           ) do
      {:ok, auth_msg, encoded_ack_resp, secrets}
    end
  end

  def decode_auth(encoded_auth_msg, my_static_private_key) do
    with {:ok, auth_msg = %Handshake.Struct.AuthMsgV4{}, <<>>} <-
           Handshake.read_auth_msg(encoded_auth_msg, my_static_private_key) do
      {:ok, auth_msg}
    end
  end

  def decode_ack(encoded_ack_resp, static_private_key) do
    with {:ok, ack_resp, _other_stuff, <<>>} <-
           ExWire.Handshake.read_ack_resp(encoded_ack_resp, static_private_key) do
      {:ok, ack_resp}
    end
  end

  def prepare_ack_response(auth_msg, my_ephemeral_key_pair) do
    auth_msg
    |> build_ack_resp()
    |> ExWire.Handshake.Struct.AckRespV4.serialize()
    |> ExWire.Handshake.EIP8.wrap_eip_8(
      auth_msg.remote_public_key,
      my_ephemeral_key_pair
    )
  end

  def derive_shared_secrets(
        auth_msg,
        encoded_auth_msg,
        encoded_ack_resp,
        my_ephemeral_key_pair,
        my_nonce
      ) do
    auth_initiator = false
    {private_key, _public_key} = my_ephemeral_key_pair

    secrets =
      ExWire.Framing.Secrets.derive_secrets(
        auth_initiator,
        private_key,
        auth_msg.remote_ephemeral_public_key,
        auth_msg.remote_nonce,
        my_nonce,
        encoded_auth_msg,
        encoded_ack_resp
      )

    {:ok, secrets}
  end

  defp build_ack_resp(auth_msg) do
    ExWire.Handshake.build_ack_resp(
      auth_msg.remote_ephemeral_public_key,
      auth_msg.remote_nonce
    )
  end
end
