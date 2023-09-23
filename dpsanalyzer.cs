using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length != 2 || args[0] != "-c")
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            string message = "⠀⠀⠀⢀⣴⣿⣶⣤⡀⠈⠂⠀⠀⠀⠀⠀⣠⣶⣿⢶⡄⠀⠀⠀⠀⠀\r\n⠀⠀⡰⣡⢫⡟⠻⣿⣿⣦⡀⠀⠀⠀⠀⣼⣿⣿⣿⠀⣿⣄⠱⡀⠀⠀\r\n⠀⢰⣡⠏⣼⠁⠀⠈⠻⣿⣿⣦⣀⣀⣼⣿⡿⠋⠈⡇⠹⣿⣆⠈⠄⠀\r\n⢀⢏⣸⣿⠇⠀⠀⠀⣠⡾⢻⣿⡿⣿⣿⣿⣷⡄⠀⢡⠀⢻⣿⣆⠈⡀\r\n⢸⣶⣿⠏⠀⠀⢀⣾⣫⣾⡞⣷⣿⣿⣿⣿⣿⣿⡆⠀⢧⠈⢿⣿⣆⠁\r\n⠘⠿⠟⠀⠀⠀⡾⣿⡿⡿⠀⠘⠃⠈⣉⡿⣿⣿⣿⡀⠈⠣⣌⣿⡟⠀\r\n⠀⠀⠀⠀⠀⠀⡇⣿⣿⡗⠿⠂⠀⠀⠙⠋⣿⣽⣿⡇⠀⠀⠀⠀⠀⠀\r\n⠀⠀⠀⠀⠀⠀⢃⢸⣿⣧⠀⠀⠀⠀⠀⠸⣿⣿⣿⣧⠀⠀                   Try; dpsanalyzer.exe -c dps-dump.txt ⠀⠀⠀⠀\r\n⠀⠀⠀⠀⠀⠀⠀⣼⢻⣿⣧⣄⣀⣀⠤⢺⣹⣿⣿⣿⡄⠀⠀                   Code: nay⠀⠀⠀Idea: kendo⠀⠀⠀⠀⠀\r\n⠀⠀⠀⠀⠀⠀⠀⣿⣾⣿⣿⡿⡓⠄⡀⠸⡿⠿⠿⢿⣿⡄⠀⠀⠀⠀\r\n⠀⠀⠀⠀⠀⠀⢸⡿⠁⠀⠘⢣⠒⠀⣾⠿⡿⠃⠀⠀⢹⣷⡀⠀⠀⠀\r\n⠀⠀⠀⠀⠀⢀⣿⡇⠀⠀⠀⡄⠀⠀⠈⠀⠀⠀⠀⠀⢄⣿⢧⠀⠀⠀\r\n⠀⠀⠀⠀⠀⣼⣿⣇⠀⠀⠀⠀⣠⠦⢄⡀⠑⡀⠀⢠⢞⢻⣞⡆⠀⠀\r\n⠀⠀⠀⠀⠀⡏⣿⢹⠀⠀⠀⢠⠇⠹⠀⠈⣲⣄⣰⣋⣀⣼⣿⣷⠀⠀\r\n⠀⠀⠀⠀⠀⡇⢻⡾⡇⠀⠀⢸⣧⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⢸⠀⠀\r\n⠀⠀⠀⠀⠀⠀⢨⣿⣿⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡟⡟⣽⣿⠈⠀⠀\r\n⠀⠀⠀⠀⠀⡠⠟⢡⣿⡇⠀⢸⣿⣿⣿⣿⣿⣿⡟⠁⡧⠃⡇⠀⠀⠀\r\n⠀⠀⠀⠀⠰⠀⢐⣡⣿⡇⠀⠀⣿⣿⣿⣿⣿⠟⠀⠀⡇⠀⠀⠁⠀⠀\r\n⠀⠀⠀⢀⠤⠚⠙⠻⣿⣇⠀⠀⣿⣿⣿⣿⡏⠀⡄⠀⡇⠀⠀⠀⠀⠀\r\n⠀⠀⠔⠁⠀⠀⠀⠀⠘⣿⡀⠀⢹⣿⣿⠞⠑⡄⠁⠀⠃⠀⠀⠀⠀";
            byte[] utf16Bytes = Encoding.Unicode.GetBytes(message);
            string decodedMessage = Encoding.Unicode.GetString(utf16Bytes);
            Console.OutputEncoding = Encoding.Unicode;
            Console.WriteLine(decodedMessage);
            Console.ReadLine();
            return;
        }

        string inputFileName = args[1];

        List<string> filteredWords = new List<string>(),
            exeAndTimeList = new List<string>(),
            suspiciousExeList = new List<string>();
        Dictionary<string, HashSet<string>> exeToDates = new Dictionary<string, HashSet<string>>();

        try
        {
            string[] lines = File.ReadAllLines(inputFileName);

            filteredWords = lines
                .SelectMany(line => Regex.Matches(line, @"!!(.*?\.exe)!(\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!").Cast<Match>())
                .Select(match => match.Value)
                .ToList();

            File.WriteAllLines("dps-query-results.txt", filteredWords);

            foreach (string word in filteredWords)
            {
                Match match = Regex.Match(word, @"!!(.*?\.exe)!(\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!");
                if (match.Success)
                {
                    string exeName = match.Groups[1].Value;
                    string dateTime = match.Groups[2].Value;
                    string entry = $"Ejecutable: {exeName}, Timestamp: {dateTime}";

                    exeAndTimeList.Add(entry);

                    if (!exeToDates.ContainsKey(exeName))
                    {
                        exeToDates[exeName] = new HashSet<string>();
                    }

                    exeToDates[exeName].Add(dateTime);
                }
            }

            File.WriteAllLines("dps-parsed-results.txt", exeAndTimeList);

            List<string> suspiciousEntries = new List<string>();
            List<string> suspiciousEntriesExe = new List<string>();

            foreach (var entry in exeToDates)
            {
                if (entry.Value.Count > 1)
                {
                    foreach (string dateTime in entry.Value)
                    {
                        suspiciousEntries.Add($"{entry.Key}!{dateTime}");
                        suspiciousEntriesExe.Add($"{entry.Key}");
                    }
                }
            }

            File.WriteAllLines("dps-suspicious-results.txt", suspiciousEntries);
            try
            {
                List<string> suspiciousPaths = new List<string>();
                suspiciousPaths.Add("Warning, not everything that appears here is suspicious");

                string[] linesE = File.ReadAllLines(inputFileName);

                foreach (string line in lines)
                {
                    if (line.Contains("HarddiskVolume"))
                    {
                        foreach (string exeName in suspiciousEntriesExe)
                        {
                            if (line.Contains(exeName))
                            {
                                suspiciousPaths.Add(line);
                            }
                        }
                    }
                }
                
                File.WriteAllLines("dps-suspicious-paths.txt", suspiciousPaths);

            } catch (Exception ex)
            {
                Console.WriteLine("Error: "+ex.Message);
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Process completed, output: 4 files");
            Console.ForegroundColor = ConsoleColor.White;

        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: "+ex.Message);
        }
    }
}
