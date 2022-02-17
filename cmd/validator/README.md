##Compile

``go build -o validator ./*.go``

##Run
###Step1: Create wallet

``./validator wallet create``

###Step2: Create account

`` ./validator accounts new --wallet-dir=./wallet ``

###Step3: Check account

``./validator accounts list --wallet-dir=./wallet``

###Step4: Run examples

``./validator example --wallet-dir=./wallet``