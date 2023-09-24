# dpsanalyzer
Command application to analyze dps
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/6cbfba68-d666-49f7-b021-f8889f74bed5)

# How to use
1. Dump dps (svchost.exe) on Process Hacker/System Informer etc..
2. Save the Search Results in the .exe directory
3. open cmd and type `dpsanalyzer.exe -c Search Results.txt` you will start the program
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/6e880720-c1a4-4c18-910b-6b71e95af0c6)
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/982b34fa-ea11-4f0a-ae47-36be7b72cfee)
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/a2c92936-77ab-4ad1-bf98-c0f4eed2e136)
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/97c201e2-96f1-4f10-94b6-7dea9b60311f)
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/4f2d8a32-537f-44b5-a661-dad64491b973)
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/6d962ea0-d98e-46b6-921c-05409bfdec6d)
![image](https://github.com/nay-cat/dpsanalyzer/assets/63517637/92916042-2d92-4532-a83c-5e774bfa9e22)


# Output files
1. `dps-parsed-results.txt` - Makes files more understandable and sorts them by name

2. `dps-query-results.txt` - All strings that contains ".exe" and "!!"

3. `dps-suspicious-results.txt` - All strings with same .exe but different timestamp

4. `dps-suspicious-paths.txt` - Paths that contains strings of dps-suspicious-results

5. `dps-parsed-paths` - Parse device path to drive path but only with duplicate executables

6. `dps-sigcheck-executables.txt` - Check signature of dps duplicate executables

7. `dps-full-sigcheck-executables.txt` - Check signature of all executables

8. `dps-executables.txt` - List all executables

9. `dps-complete-parsed-paths.txt` - Parse device path to drive path with all executables

10. `dps-full-unsigned-executables.txt` - Check all unsigned executables

11. `dps-sorted-suspicious-results.txt` - All strings with same .exe but different timestamp but sorted
