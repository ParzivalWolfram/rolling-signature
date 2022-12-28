from sys import argv
from random import randint
from os import remove as deleteFile
from hashlib import algorithms_available as hashModeList
from hashlib import new as newHash

helpFlag = '--help'
modeOutFlag = '--create'
modeInFlag = '--verify'
testFlag = '--test'
secret = ''
mode = -1
blockSizeList = [16,16,16,32,128,512,1024,2048,8192,32768,262144,1048576,4194304,16777216,67108864]

helpText = '''
rolling-hash.py:
        --help - Display this text
        --create <filename> - Create a rolling hash signature for a target file.
        --verify <filename> <hashfile> - Verify a file using a rolling hash signature.
        --test - Perform a benchmark (will create and remove many files in the working directory)
'''

#actual function
def keyhash_main(filename, secret, blockSize=512, hashMode='sha512', checkHash=None, debug=False):
        
        if debug:
                print("DEBUG: hashModeList="+str(hashModeList))
        
        if hashMode not in hashModeList:
                return None
        
        try:
                fileHandle = open(filename,"rb")
        except:
                return None

        fileHandleSize = fileHandle.seek(0,2)
        currentOffset = fileHandle.seek(0,0)
        blockList = []
        hashList = []

        
        blockList.append(fileHandle.read(blockSize)+bytes(secret,'utf-8'))
        hashList.append(newHash(hashMode,blockList[0]).hexdigest())
        if checkHash != None and hashList[0] != checkHash:
                return None
        while fileHandle.seek(0,1) < fileHandleSize:
                blockList.append(fileHandle.read(blockSize)+bytes(hashList[-1],'utf-8'))
                hashList.append(newHash(hashMode,blockList[-1]).hexdigest())
                
                if debug:
                        print('DEBUG: hashList[-1]='+str(hashList[-1]))

        return hashList


#test function
def test_keyhash_main(testCount,blockSize=512,hashMode='sha512'):

        print("TESTING: Generating test files...")

        loopnum = 0

        while loopnum < testCount:
                fileName = 'test'+str(loopnum)+'.bin'
                fileHandle = open(fileName,'w')
                fileHandle.write(getRandomString(32*blockSize))
                fileHandle.flush()
                fileHandle.close()
                loopnum += 1

        testResults = []
        keysUsed = []
        testNum = 0
        fileName = 'test'+str(testNum)+'.bin'

        for i in range(testCount):
                fileName = 'test'+str(i)+'.bin'
                keysUsed.append(getRandomString(64))
                testResults.append(keyhash_main(fileName,keysUsed[-1],blockSize,hashMode))
                print("TEST "+str(i+1)+":\n\nAlgorithm: "+str(hashMode)+"\nRolling Block Size: "+str(blockSize)+"\n\nKey: "+str(keysUsed[-1])+"\n\nHashed Results: "+str(testResults[-1])+"\n\n")
                deleteFile(fileName)
                testNum += 1

#test helper function
def getRandomString(length):
        from random import randint
        stringBuffer = ''
        for i in range(length):
                stringBuffer += chr(randint(40,126))
        return stringBuffer


def doTests():
        #each test should use 6MB or so
        test_keyhash_main(400,512,'blake2b')
        test_keyhash_main(100,2048,'sha512')
        test_keyhash_main(25,8192,'sha3_256')
        exit(0)

def printHelp():
        print(helpText)
        exit(0)

def checkArgvLength(targetLength,inputFlag):
        argvBuf = argv[argv.index(inputFlag):]
        if len(argvBuf) < targetLength:
                printHelp()
        return argvBuf[1:]

def getAndCheckInput(prompt,options,enterOnly=True):
        while True:
                result = input(prompt)
                if result in options or result == '':
                        break
                print("\n\nOption not valid. Try again.\n\n")
        return result

#parse individual flags
if helpFlag in argv:
        printHelp()
if testFlag in argv:
        doTests()
elif modeOutFlag in argv:
        mode = 0
elif modeInFlag in argv:
        mode = 1
else:
        printHelp()

#verify filename counts
if mode == 0:
        result = checkArgvLength(1,modeOutFlag)
elif mode == 1:
        result = checkArgvLength(2,modeInFlag)

#verify filenames are actually filenames
for i in result:
        try:
                open(str(i),"r")
        except:
                printHelp()
                
if mode == 0:
        inputFilename = result[0]
        fileBuf = open(inputFilename,'rb')
        fileSize = int(fileBuf.seek(0,2))
        fileBuf.close()
        secret = input('Please input a password or passphrase to protect the hashfile.\nInput> ')
        hashtype = getAndCheckInput('Please input an option for hashing algorithm. If you are unsure about this option, just press Enter.\nOptions:\n'+str(str(sorted(hashModeList))[1:-2].replace('\'',''))+'\n\nInput> ',hashModeList)
        if hashtype == '':
                hashtype = 'sha512'
        try:
                blockSize = blockSizeList[len(str(fileSize))]
        except:
                blockSize = blockSizeList[-1]
        print("Building signature, please wait...")
        result = keyhash_main(inputFilename,secret,blockSize,hashtype)
        print('Building hashfile, please wait...')
        outputFile = open(inputFilename+'.hash','w')
        sep = '|'
        outputBuf = hashtype+sep+str(blockSize)+sep
        for i in result:
                outputBuf += str(i)+sep
        outputBuf = outputBuf[:-1]
        outputFile.write(outputBuf)
        outputFile.flush()
        outputFile.close()
        print('\n\n\n\nHashfile saved at '+str(inputFilename+'.hash'))

elif mode == 1:
        inputDataFilename = result[0]
        inputHashFilename = result[1]
        inputBlockList = []
        inputHashHandle = open(str(inputHashFilename),'r')
        inputBuf = inputHashHandle.read().split('|')
        if inputBuf[0] not in hashModeList:
                print('ERROR: Hash method not available on this machine!')
                exit(1)
        hashtype = inputBuf[0]
        blockSize = int(inputBuf[1])
        firstHash = inputBuf[2]
        del inputBuf[0]
        del inputBuf[0]
        for i in inputBuf:
                inputBlockList.append(i)
        del inputBuf
        secret = input('Please input the password or passphrase protecting the hashfile.\nInput> ')
        result = keyhash_main(inputDataFilename,secret,blockSize,hashtype,firstHash)
        if result == None:
                print('First block is incorrect. Either password/passphrase is wrong, or rolling hash signature is invalid.')
                exit(2)
        if len(result) != len(inputBlockList):
                print('Input file size has dramatically changed. Signature is invalid.')
                exit(2)
        loopnum = 0
        while loopnum != len(inputBlockList):
                if inputBlockList[loopnum] != result[loopnum]:
                        print('Block '+str(loopnum+1)+' failed validation. Signature is invalid.')
                        print(str(inputBlockList[loopnum])+str(' != ')+str(result[loopnum]))
                        exit(2)
                loopnum+=1
        print('All blocks validated. File has not been modified.')
