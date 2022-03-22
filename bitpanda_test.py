from algosdk import algod, transaction

algod_address = "https://testnet-algorand.api.purestake.io/ps1"                
algod_token = ""
headers = {
   "X-API-Key": "zsM21vy2X729LY6BCEmnY8NcS61uH50N81SivqFl",
}

algodclient = algod.AlgodClient(algod_token, algod_address, headers)
params = algodclient.suggested_params()
genesis_hash = params.get('genesishashb64')
genesis_id = params.get('genesisID')
first_valid = params.get('lastRound')
last_valid = first_valid + 1000
fee_per_byte = params.get('fee')

alice = "THQHGD4HEESOPSJJYYF34MWKOI57HXBX4XR63EPBKCWPOJG5KUPDJ7QJCM"
bob = "AJNNFQN7DSR7QEY766V7JDG35OPM53ZSNF7CU264AWOOUGSZBMLMSKCRIU"
charlie = "3ZQ3SHCYIKSGK7MTZ7PE7S6EDOFWLKDQ6RYYVMT7OHNQ4UJ774LE52AQCU"
 
def scenario1():
    """
    Alice sends 100 Algos to Bob with flat fee.
    """

    amount = 100000000
    fee = 1000

    data = (alice, fee, first_valid, last_valid, genesis_hash, bob, amount)
    data_add = {
        "gen": genesis_id,
        "flat_fee": True 
        }

    tx = transaction.PaymentTxn(*data, **data_add)
    return tx

def scenario2():
    """
    Alice sends 100 Algos to Bob with suggested fee and a 1 KB note.
    """

    amount = 100000000
    note = b''.join(b'a' for item in range(1000))
    data = (alice, fee_per_byte, first_valid, last_valid, genesis_hash, 
                bob, amount)
    data_add = {
        "gen": genesis_id,
        "note": note
        }

    tx = transaction.PaymentTxn(*data, **data_add)
    return tx

def scenario3():
    """
    Alice transfers all her algos to Bob.
    """
    amount = 1
    fee = 1000
    data = (alice, fee, first_valid, last_valid, genesis_hash, bob, amount)
    data_add = {
        "gen": genesis_id,
        "flat_fee": True,
        "close_remainder_to": bob
        }
    tx = transaction.PaymentTxn(*data, **data_add)
    return tx

def scenario4(spb=4.5):
    """
    Alice sends 100 algos to Bob in 24 hours from now.
    """

    amount = 100000000
    fee = 1000
    
    future_first_valid = first_valid + int(24*60*60/spb)
    future_last_valid = future_first_valid + 1000

    data = (alice, fee, future_first_valid, future_last_valid, genesis_hash, 
                bob, amount)
    data_add = {
        "gen": genesis_id,
        "flat_fee": True
        }
    tx = transaction.PaymentTxn(*data, **data_add)
    return tx

def scenario5():
    """
    Alice and Bob send 100 algos to Charlie from a joint multisignature 
    account.
    """
 
    alice_bob_multisig = transaction.Multisig(1, 2, [alice, bob])
    msig_address = alice_bob_multisig.address()
    print("Alice and Bob's Multisig Address: {}".format(msig_address))
 
    amount = 100000000
    fee = 1000
    data = (msig_address, fee, first_valid, last_valid, genesis_hash, charlie, 
                amount)
    data_add = {
        "gen": genesis_id,
        "flat_fee": True 
        }
    tx = transaction.PaymentTxn(*data, **data_add)
    tx_with_multisig = transaction.MultisigTransaction(tx, alice_bob_multisig)
    return (tx, tx_with_multisig)

def main():
    txn1 = scenario1()
    txn2 = scenario2()
    txn3 = scenario3()
    txn4 = scenario4()
    txn5a, txn5b = scenario5()

    print("Writing transactions to files...")
    transaction.write_to_file([txn1, txn2, txn3, txn4], 'alice_sender_testnet.tx')
    transaction.write_to_file([txn5a], "alice_bob_no_multisig.tx")
    transaction.write_to_file([txn5b], "alice_bob_with_multisig.tx")
    print("Done.")

if __name__ == "__main__":
    main()
    