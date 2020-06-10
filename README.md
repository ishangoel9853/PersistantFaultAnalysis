# PersistantFaultAnalysis

This is the c++ code for Persistant Fault Analysis Attack on DES Cipher.

## Files:

des.h : The DES Class header file
attack.cpp : Fault Injection and Complete Attack Procedure


## Instructions:

	g++ -std=c++11 attack.cpp 
	./a.out

## Inputs:

The programs automatically generated all inputs randomly (PTs, K).
The 2 constants to set at the top of the code are:
1) N : Number of Queries for each attack
2) NA : Number of Attacks

Change them to change the attack analysis accordingly



## Outputs:

The program generates 4 output files which are all csv (comma seperated values):
1) NumberOfSolved_Single.csv:

It represents the number of attacks which has successfully completed till a particular query number. The file contains 8 rows for attacking each S-Box. Each row contains N values each representing the number of completed attack till the ith query.

2) NumberOfSolved_Multi.csv:

It represents the number of attacks which has successfully completed till a particular query number. The file contains 1 row which is attacking all S-Box together. The row contains N values each representing the number of completed attack till the ith query.

3) KeySpace_Single.csv:
It represents the average remaining Key Space after a particular query number. The file contains 8 row each attacking a S-Box. The row contains N values each representing the average remaining Key Space till the ith query.


4) KeySpace_Multi.csv:
It represents the average remaining Key Space after a particular query number. The file contains 1 row which is attacking all S-Box together. The row contains N values each representing the average remaining Key Space till the ith query.