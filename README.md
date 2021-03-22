# simple-crypto

A simple crypto script to encrypt / decrypt text with AES256.

## Install

```
git pull https://github.com/vladiuz1/simple-crypto.git
cd simple-crypto
python3 -m pip install -r requirements.txt
```

## Encrypt text

Any of these command lines will work:

```
echo "The quick brown fox jumps over the lazy dog" | python3 simpleAES.py -s encrypt
python3 simpleAES.py -t "The quick brown fox jumps over the lazy dog" encrypt
python3 simpleAES.py -f source.file.txt encrypt
cat source.file.txt | python3 simpleAES.py -s encrypt
```

The output of the script will be something like:

```
{
  "iv": "292a4eb01098fd5d6825a3d70ea9ecf0",
  "cipher-text": "ec1ebf326f08abea01a2a2bb66368f9b192c8e7a9d1f1a642599a7370fb617703e8d4f9b3cda34bb4825565a288849db968aaf9260eaf9c5fdc51deadc9a82bc",
  "read-more": "https://github.com/vladiuz1/simple-crypto"
}
```

## Decrypt json object

To decrypt the result of the encryption simply use:

```
python3 simpleAES.py -f encrypted.obj.json decrypt
cat encrypted.obj.json | python3 -s simpleAES.py decrypt
```

## Help

```
python3 simpleAES.py --help
```