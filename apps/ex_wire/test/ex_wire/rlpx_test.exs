defmodule ExWire.RLPxTest do
  use ExUnit.Case, async: true
  doctest ExWire.RLPx

  alias ExWire.{RLPx, Handshake}
  alias ExWire.Framing.Secrets
  alias ExthCrypto.ECIES.ECDH

  describe "handles a crypto handshake" do
    test "when we send auth and remote sends ack" do
      creds = build_all_credentials()

      handshake = %Handshake{
        initiator: true,
        public_key: creds.my_static_public_key,
        remote_public_key: creds.her_static_public_key,
        init_nonce: creds.my_nonce,
        resp_nonce: creds.her_nonce,
        ephemeral_key_pair: creds.my_ephemeral_key_pair
      }

      # we generate our encoded auth message
      {:ok, encoded_auth_msg} = RLPx.prepare_auth_message(handshake, creds.my_static_private_key)

      # remote receives and decodes it
      {:ok, her_decoded_auth_msg} =
        RLPx.decode_auth(encoded_auth_msg, creds.her_static_private_key)

      # remote generates ack response based on auth msg
      {:ok, her_encoded_ack_resp} =
        RLPx.prepare_ack_response(her_decoded_auth_msg, creds.her_ephemeral_key_pair)

      # remote sends ack and we decode it
      {:ok, my_decoded_ack_resp} =
        RLPx.decode_ack(her_encoded_ack_resp, creds.my_static_private_key)

      # when we encoded the auth message, we sent our ephemeral public key. If
      # remote successfully received it, she should have included it in the ack
      # response. So we can check the ack response for our own ephemeral pulic
      # key to make sure she successfully decoded things correctly
      {my_ephemeral_public_key, _private_key} = creds.my_ephemeral_key_pair
      assert my_decoded_ack_resp.remote_ephemeral_public_key == my_ephemeral_public_key
      assert my_decoded_ack_resp.remote_nonce == creds.my_nonce
    end

    test "when remote sends auth and we send ack" do
      creds = build_all_credentials()
      {_, her_encoded_auth_msg} = build_her_auth_message(creds)

      # remote sends us an auth msg and we decode
      {:ok, my_decoded_auth_msg} =
        RLPx.decode_auth(her_encoded_auth_msg, creds.my_static_private_key)

      # generate ack response based on auth msg
      {:ok, my_encoded_ack_resp} =
        RLPx.prepare_ack_response(my_decoded_auth_msg, creds.my_ephemeral_key_pair)

      # we send ack and remote decodes
      {:ok, her_decoded_ack_resp} =
        RLPx.decode_ack(my_encoded_ack_resp, creds.her_static_private_key)

      # when she decodes the ack we sent, she should be able to see the ephemeral
      # key which was in the body of the auth message. This means we
      # successfully decoded the body and returned her own public key to show
      # her that we indeed decoded the messages successfully
      {her_ephemeral_public_key, _private_key} = creds.her_ephemeral_key_pair
      assert her_decoded_ack_resp.remote_ephemeral_public_key == her_ephemeral_public_key
      assert her_decoded_ack_resp.remote_nonce == creds.her_nonce
    end
  end

  describe "decode_auth/2" do
    test "decodes encoded auth message remote (Alice) sends us" do
      creds = build_all_credentials()
      {her_unencoded_auth_msg, her_encoded_auth_msg} = build_her_auth_message(creds)

      {:ok, auth_msg} = RLPx.decode_auth(her_encoded_auth_msg, creds.my_static_private_key)

      assert her_unencoded_auth_msg == remove_remote_public_key(auth_msg)
    end
  end

  describe "prepare_auth_message" do
    test "generates an encoded auth message" do
      creds = build_all_credentials()

      handshake = %Handshake{
        initiator: true,
        public_key: creds.my_static_public_key,
        remote_public_key: creds.her_static_public_key,
        init_nonce: creds.my_nonce,
        resp_nonce: creds.her_nonce,
        ephemeral_key_pair: creds.my_ephemeral_key_pair
      }

      {:ok, encoded_auth_msg} = RLPx.prepare_auth_message(handshake, creds.my_static_private_key)

      assert is_binary(encoded_auth_msg)
    end
  end

  describe "prepare_ack_response/2" do
    test "generates an ack response and encodes it, in response to an auth msg" do
      creds = build_all_credentials()
      {_, her_encoded_auth_msg} = build_her_auth_message(creds)

      {:ok, auth_msg} = RLPx.decode_auth(her_encoded_auth_msg, creds.my_static_private_key)
      {:ok, encoded_ack_resp} = RLPx.prepare_ack_response(auth_msg, creds.my_ephemeral_key_pair)

      assert is_binary(encoded_ack_resp)
    end
  end

  describe "derive_shared_secrets/3" do
    test "it generates all shared secrets from an auth_msg and ack_resp" do
      creds = build_all_credentials()

      handshake = %Handshake{
        initiator: true,
        public_key: creds.my_static_public_key,
        remote_public_key: creds.her_static_public_key,
        init_nonce: creds.my_nonce,
        ephemeral_key_pair: creds.my_ephemeral_key_pair
      }

      {:ok, encoded_auth_msg} = RLPx.prepare_auth_message(handshake, creds.my_static_private_key)

      {:ok, her_decoded_auth_msg} =
        RLPx.decode_auth(encoded_auth_msg, creds.her_static_private_key)

      {:ok, her_encoded_ack_resp} =
        RLPx.prepare_ack_response(her_decoded_auth_msg, creds.her_ephemeral_key_pair)

      {:ok, my_decoded_ack_resp} =
        RLPx.decode_ack(her_encoded_ack_resp, creds.my_static_private_key)

      new_handshake = RLPx.add_ack_data(handshake, my_decoded_ack_resp)

      {:ok, secrets} =
        RLPx.derive_shared_secrets(
          new_handshake,
          encoded_auth_msg,
          her_encoded_ack_resp
        )

      assert %Secrets{} = secrets
    end
  end

  def remove_remote_public_key(auth_message) do
    %{auth_message | remote_ephemeral_public_key: nil}
  end

  def build_all_credentials do
    keys = build_keys()

    keys
    |> Map.merge(build_my_credentials())
    |> Map.merge(build_her_credentials())
  end

  def build_keys do
    %{
      my_static_public_key: ExthCrypto.Test.public_key(:key_a),
      my_static_private_key: ExthCrypto.Test.private_key(:key_a),
      her_static_public_key: ExthCrypto.Test.public_key(:key_b),
      her_static_private_key: ExthCrypto.Test.private_key(:key_b)
    }
  end

  def build_my_credentials do
    %{
      my_ephemeral_key_pair: ECDH.new_ecdh_keypair(),
      my_nonce: Handshake.new_nonce()
    }
  end

  def build_her_credentials do
    %{
      her_ephemeral_key_pair: ECDH.new_ecdh_keypair(),
      her_nonce: Handshake.new_nonce()
    }
  end

  def build_her_auth_message(creds) do
    {auth_msg, _, _} =
      Handshake.build_auth_msg(
        creds.her_static_public_key,
        creds.her_static_private_key,
        creds.my_static_public_key,
        creds.her_nonce,
        creds.her_ephemeral_key_pair
      )

    {:ok, encoded_auth_msg} =
      auth_msg
      |> Handshake.Struct.AuthMsgV4.serialize()
      |> Handshake.EIP8.wrap_eip_8(creds.my_static_public_key, creds.her_ephemeral_key_pair)

    {auth_msg, encoded_auth_msg}
  end
end
