defmodule EVM.Configuration.EIP150 do
  defstruct extcodesize_cost: 700,
            extcodecopy_cost: 700,
            balance_cost: 400,
            sload_cost: 200,
            call_cost: 700,
            selfdestruct_cost: 5_000,
            new_account_destruction_cost: 25_000,
            fail_nested_operation: false,
            fallback_config: EVM.Configuration.Homestead.new()

  def new do
    %__MODULE__{}
  end
end

defimpl EVM.Configuration, for: EVM.Configuration.EIP150 do
  alias EVM.Configuration

  @spec contract_creation_cost(Configuration.t()) :: integer()
  def contract_creation_cost(config), do: config.fallback_config.contract_creation_cost

  @spec has_delegate_call?(Configuration.t()) :: boolean()
  def has_delegate_call?(config), do: config.fallback_config.has_delegate_call

  @spec max_signature_s(Configuration.t()) :: atom()
  def max_signature_s(config), do: Configuration.max_signature_s(config.fallback_config)

  @spec fail_contract_creation_lack_of_gas?(Configuration.t()) :: boolean()
  def fail_contract_creation_lack_of_gas?(config),
    do: config.fallback_config.fail_contract_creation

  @spec extcodesize_cost(Configuration.t()) :: integer()
  def extcodesize_cost(config), do: config.extcodesize_cost

  @spec extcodecopy_cost(Configuration.t()) :: integer()
  def extcodecopy_cost(config), do: config.extcodecopy_cost

  @spec balance_cost(Configuration.t()) :: integer()
  def balance_cost(config), do: config.balance_cost

  @spec sload_cost(Configuration.t()) :: integer()
  def sload_cost(config), do: config.sload_cost

  @spec call_cost(Configuration.t()) :: integer()
  def call_cost(config), do: config.call_cost

  @spec selfdestruct_cost(Configuration.t(), keyword()) :: integer()
  def selfdestruct_cost(config, new_account: false), do: config.selfdestruct_cost

  def selfdestruct_cost(config, new_account: true) do
    config.selfdestruct_cost + config.new_account_destruction_cost
  end

  @spec fail_nested_operation_lack_of_gas?(Configuration.t()) :: boolean()
  def fail_nested_operation_lack_of_gas?(config), do: config.fail_nested_operation

  @spec exp_byte_cost(Configuration.t()) :: integer()
  def exp_byte_cost(config), do: Configuration.exp_byte_cost(config.fallback_config)

  @spec limit_contract_code_size?(Configuration.t(), integer()) :: boolean()
  def limit_contract_code_size?(config, _),
    do: Configuration.limit_contract_code_size?(config.fallback_config)

  @spec increment_nonce_on_create?(Configuration.t()) :: boolean()
  def increment_nonce_on_create?(config),
    do: Configuration.increment_nonce_on_create?(config.fallback_config)

  @spec empty_account_value_transfer?(Configuration.t()) :: boolean()
  def empty_account_value_transfer?(config),
    do: Configuration.empty_account_value_transfer?(config.fallback_config)

  @spec clean_touched_accounts?(Configuration.t()) :: boolean()
  def clean_touched_accounts?(config),
    do: Configuration.clean_touched_accounts?(config.fallback_config)

  @spec has_revert?(Configuration.t()) :: boolean()
  def has_revert?(config), do: Configuration.has_revert?(config.fallback_config)

  @spec has_static_call?(Configuration.t()) :: boolean()
  def has_static_call?(config), do: Configuration.has_static_call?(config.fallback_config)

  @spec support_variable_length_return_value?(Configuration.t()) :: boolean()
  def support_variable_length_return_value?(config),
    do: Configuration.support_variable_length_return_value?(config.fallback_config)

  @spec has_mod_exp_builtin?(Configuration.t()) :: boolean()
  def has_mod_exp_builtin?(config), do: Configuration.has_mod_exp_builtin?(config.fallback_config)

  @spec has_ec_add_builtin?(Configuration.t()) :: boolean()
  def has_ec_add_builtin?(config), do: Configuration.has_ec_add_builtin?(config.fallback_config)

  @spec has_ec_mult_builtin?(Configuration.t()) :: boolean()
  def has_ec_mult_builtin?(config), do: Configuration.has_ec_mult_builtin?(config.fallback_config)

  @spec has_ec_pairing_builtin?(Configuration.t()) :: boolean()
  def has_ec_pairing_builtin?(config),
    do: Configuration.has_ec_pairing_builtin?(config.fallback_config)

  @spec has_shift_operations?(Configuration.t()) :: boolean()
  def has_shift_operations?(config),
    do: Configuration.has_shift_operations?(config.fallback_config)

  @spec has_extcodehash?(Configuration.t()) :: boolean()
  def has_extcodehash?(config), do: Configuration.has_extcodehash?(config.fallback_config)
end
