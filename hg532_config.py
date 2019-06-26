#!/usr/bin/python
import sys
import os
from binascii import hexlify, unhexlify 
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import number


RSA_D = "1B18D0048611500CA489C51D7389B19A" \
	"F977E6F5BB8DD5E61A62E339499E6237" \
	"C234740129EBD25EF226AB7E498A0830" \
	"DF0A5D45F19F5055B906EBC5E71C16C5" \
	"A99E36D4F369701FAE2403E445BA3CAE" \
	"4B0C9526A82EDD90FECD78B7EDD5EA5E" \
	"6C98A0C4CABF3148E99E78DA0D5EB972" \
	"6F1533A6738F47C790037D532F403C0D"

RSA_N = "A93591A1BFCB7615555C12CFE3AF0B68" \
	"5A6B94E8604A9441ABF7A5F268D4CBF9" \
	"6022E2F0694D679D2C8E4C2D4C3C0C44" \
	"60C5646E852A51EF7EBC2F0C88F08E80" \
	"6D991446348EB7AF280E607DDA363F4F" \
	"322E9B5005503F31F60353219F86443A" \
	"04E573FFEF541D21ADD1043E478D81B1" \
	"E79A5B434C5F64B3D5B141D7BEB59D71"

RSA_E = "010001"
	       
SIG_TEMPLATE = "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
               "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
               "003021300906052B0E03021A05000420"

AES128CBC_KEY = "3E4F5612EF64305955D543B0AE350880"
AES128CBC_IV = "8049E91025A6B54876C3B4868090D3FC"

XML_VERSION_STRING = b'<?xml version="1.0" ?>'

def print_usage():
	print("Usage : " + sys.argv[0] + " {encrypt | decrypt} input_file output_file")
	sys.exit(1)

def load_config(config_file):
	if os.path.isfile(config_file):
		cf = open(config_file, "rb")
		config = cf.read()
		cf.close()
	else:
		print("Config file not found..exiting")
		sys.exit(1) 
	return config

def save_to_file(dest_file, data):
	wfile = open(dest_file,"wb")
	wfile.write(data)
	wfile.close()

def get_sha256_hash_from_sig(sig):
	sig_int = int(hexlify(sig),16)
	rsa_n = int(RSA_N,16)
	dec_sig_as_int = pow(sig_int, 0x10001, rsa_n );
	decrypted_sig = number.long_to_bytes(dec_sig_as_int, 128)
	target_sha256 = hexlify(decrypted_sig)[-64:]
	return target_sha256

def calc_actual_sha256_hash(enc_config_body):
	sha256 = SHA256.new()
	sha256.update(enc_config_body)
	actual_sha256_sig = sha256.hexdigest()
	actual_sha256_sig = str.encode(actual_sha256_sig)
	return actual_sha256_sig

def decrypt_body(enc_config_body):
	iv = unhexlify(AES128CBC_IV)
	key= unhexlify(AES128CBC_KEY)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted_data = cipher.decrypt(enc_config_body)
	# Strip block padding
	decrypted_data=decrypted_data.rstrip(b'\0')
	return decrypted_data


def decrypt_config(input_file, output_file):
	enc_config=load_config(input_file)
	sig = enc_config[:0x80]
	enc_config_body=enc_config[0x80:]

	print("verifying signature...")
	target_sha256_hash = get_sha256_hash_from_sig(sig)
	actual_sha256_hash = calc_actual_sha256_hash(enc_config_body)

	if (actual_sha256_hash == target_sha256_hash):
		print("Signature ok...")		
	else:
		print("Signature not ok...exiting")
		sys.exit(1)

	print("Decrypting...")
	decrypted_data = decrypt_body(enc_config_body)

	#check_config(decrypted_data)

	print("Saving decrypted config to " + output_file + "...")
	save_to_file(output_file, decrypted_data)

#def check_config(new_config_file):
#	head = new_config_file[0:len(XML_VERSION_STRING)]
#	if head != XML_VERSION_STRING:
#		print("Not a valid config file...exiting")
#		sys.exit(1)

def encrypt_config(input_file, output_file):
	new_config_file=load_config(input_file)

	#check_config(new_config_file)

	padding_amount = len(new_config_file) % 32
	print("" + str(padding_amount) + " bytes padding needed")
	print("Adding padding...")
	new_config_file=new_config_file + b'\0'*(32-padding_amount)

	print("Encrypting config...")
	iv = unhexlify(AES128CBC_IV)
	key= unhexlify(AES128CBC_KEY)
	aes = AES.new(key, AES.MODE_CBC, iv)
	enc_new_config = aes.encrypt(new_config_file)

	print("Calculating SHA256 hash...")
	h = SHA256.new()
	h.update(enc_new_config)
	actual_sha256_sig = h.hexdigest()

	sig = SIG_TEMPLATE+actual_sha256_sig;

	print("Encrypting Signature...")
	sig_int = int(sig,16)
	rsa_d = int(RSA_D,16)
	rsa_n = int(RSA_N,16)
	enc_sig_int = pow(sig_int, rsa_d, rsa_n);

	encrypted_sig = number.long_to_bytes(enc_sig_int, 128)
	enc_config = encrypted_sig + enc_new_config

	print("Saving encrypted config to " + output_file + "...")
	save_to_file(output_file, enc_config)

def main():

	if len(sys.argv) < 4:
		print_usage()

	input_file = sys.argv[2]
	output_file = sys.argv[3]
	command = sys.argv[1]

	if (command == "encrypt"):
		encrypt_config(input_file, output_file)
	elif (command == "decrypt"):
		decrypt_config(input_file, output_file)	
	else: 
		print_usage()



if __name__ == "__main__":
	main()
