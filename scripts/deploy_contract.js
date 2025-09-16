const { Web3 } = require('web3');
const fs = require('fs');
const path = require('path');

// Load environment variables
require('dotenv').config();

async function deployContract() {
  // Setup Web3
  const rpcUrl = process.env.BLOCKCHAIN_RPC || 'http://localhost:8545';
  const web3 = new Web3(rpcUrl);
  
  // Load account
  const privateKey = process.env.RELAYER_PRIVATE_KEY;
  if (!privateKey) {
    console.error('RELAYER_PRIVATE_KEY not set');
    process.exit(1);
  }
  
  const account = web3.eth.accounts.privateKeyToAccount(privateKey);
  web3.eth.accounts.wallet.add(account);
  web3.eth.defaultAccount = account.address;
  
  // Load contract ABI and bytecode
  const contractPath = path.join(__dirname, '../contracts/AnchorRegistry.sol');
  const compiled = JSON.parse(fs.readFileSync('./build/contracts/AnchorRegistry.json', 'utf8'));
  const abi = compiled.abi;
  const bytecode = compiled.bytecode;
  
  // Deploy contract
  const contract = new web3.eth.Contract(abi);
  const deployTx = contract.deploy({
    data: bytecode,
    arguments: []
  });
  
  try {
    const gas = await deployTx.estimateGas();
    const gasPrice = await web3.eth.getGasPrice();
    
    const deployedContract = await deployTx.send({
      from: account.address,
      gas,
      gasPrice
    });
    
    console.log('Contract deployed at address:', deployedContract.options.address);
    console.log('Transaction hash:', deployedContract.transactionHash);
    
    // Save the address to .env
    const envPath = path.join(__dirname, '../.env');
    let envContent = fs.readFileSync(envPath, 'utf8');
    
    // Update or add CONTRACT_ADDRESS
    if (envContent.includes('CONTRACT_ADDRESS=')) {
      envContent = envContent.replace(
        /CONTRACT_ADDRESS=.*/,
        `CONTRACT_ADDRESS=${deployedContract.options.address}`
      );
    } else {
      envContent += `\nCONTRACT_ADDRESS=${deployedContract.options.address}`;
    }
    
    fs.writeFileSync(envPath, envContent);
    console.log('Updated .env with contract address');
    
  } catch (error) {
    console.error('Deployment failed:', error);
  }
}

deployContract();