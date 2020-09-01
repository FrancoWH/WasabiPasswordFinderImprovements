using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using Mono.Options;
using NBitcoin;


namespace WasabiPasswordFinder
{
    internal class Program
    {
        private static Dictionary<string, string> Charsets = new Dictionary<string, string>{
            ["en"] = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            ["es"] = "aábcdeéfghiíjkmnñoópqrstuúüvwxyzAÁBCDEÉFGHIÍJKLMNNOÓPQRSTUÚÜVWXYZ",
            ["pt"] = "aáàâābcçdeéêfghiíjkmnoóôōpqrstuúvwxyzAÁÀÂĀBCÇDEÉÊFGHIÍJKMNOÓÔŌPQRSTUÚVWXYZ",
            ["it"] = "abcdefghimnopqrstuvxyzABCDEFGHILMNOPQRSTUVXYZ",
            ["fr"] = "aâàbcçdæeéèëœfghiîïjkmnoôpqrstuùüvwxyÿzAÂÀBCÇDÆEÉÈËŒFGHIÎÏJKMNOÔPQRSTUÙÜVWXYŸZ",
        };


        private static Dictionary<char, string> TypoChars = new Dictionary<char, string>{ //Multiple language support in the future
                ['a'] = "Aqwsxz\\", ['b'] = "Bvghn ", ['c'] = "Cxdfv ", ['d'] = "Dserfcx", ['e'] = "Ew234rsdf",
                ['f'] = "Fdrtgcv", ['g'] = "Gftyhvb", ['h'] = "Hgyujbn", ['k'] = "Kjiol,m", ['l'] = "Lkop;.,",
                ['m'] = "Mnjk, ", ['n'] = "N bhjm", ['o'] = "Oi890plk", ['p'] = "Po90-[;l", ['q'] = "Q`12wa",
                ['r'] = "Re345tfd", ['s'] = "Sawedzx", ['v'] = "Vcfgb ", ['w'] = "Wq123eas", ['x'] = "Xzsdc ",
                ['y'] = "Yt567ugh", ['z'] = "Z\\asx|ASX",

                ['A'] = "aQWSZ\\", ['B'] = "bVGHN ", ['C'] = "cXDFV ", ['D'] = "dSERFXC", ['E'] = "eW234RSDF",
                ['F'] = "fDRTGCV", ['G'] = "gFTYHVB", ['H'] = "hGYUJBN", ['K'] = "kJIOL,M", ['L'] = "lKOP;.,",
                ['M'] = "mNJK, ", ['N'] = "N bhjm", ['O'] = "N bhjm", ['P'] = "N bhjm", ['Q'] = "N bhjm",
                ['R'] = "N bhjm", ['S'] = "N bhjm", ['V'] = "N bhjm", ['W'] = "Wq123eas", ['X'] = "N bhjm",
                ['Y'] = "Yt567ugh", ['Z'] = "Z\\asx|ASX",

                ['0'] = "N bhjm", ['1'] = "!`2qw", ['2'] = "N bhjm", ['3'] = "£24wer", ['4'] = "N bhjm",
                ['5'] = "N bhjm", ['6'] = "N bhjm", ['7'] = "&68yui", ['8'] = "N bhjm", ['9'] = "N bhjm",
                
                ['.'] = ">,l;/",
                
                
            };
        private static double averageCharLength = 6.4375; //Make this automatic

        private static void Main(string[] args)
        {
            var language   = "en";
            var useNumbers = true;
            var useSymbols = true;
            var secret     = string.Empty;
            var help       = false;
            var mode       = "allchars";

            var options = new OptionSet () {
                { "s|secret=", "The secret from your .json file (EncryptedSecret).",
                    v => secret = v },
                { "l|language=", "The charset to use: en, es, it, fr, pt. Default=en.",
                    v => language = v },
                { "n|numbers=", "Try passwords with numbers. Default=true.",
                    v => useNumbers = (v=="" || v=="1" || v.ToUpper()=="TRUE") },
                { "x|symbols=", "Try passwords with symbolds. Default=true.",
                    v => useSymbols = (v=="" || v=="1" || v.ToUpper()=="TRUE") },
                { "h|help", "Show Help",
                    v => help = true},
                { "m|mode", "set mode e.g. allchars, shiftError,",
                    v => mode = v }};

            options.Parse(args);
            if (help || string.IsNullOrEmpty(secret) || !Charsets.ContainsKey(language))
            {
                ShowHelp(options);
                return;
            }

            BitcoinEncryptedSecretNoEC encryptedSecret;
            try
            {
                encryptedSecret = new BitcoinEncryptedSecretNoEC(secret);
            }
            catch(FormatException)
            {
                Console.WriteLine("ERROR: The encrypted secret is invalid. Make sure you copied correctly from your wallet file.");
                return;
            }
            Console.WriteLine("Confirming this is Frank's version");
            Console.WriteLine($"WARNING: This tool will display you password if it finds it. Also, the process status display your wong password chars.");
            Console.WriteLine($"         You can cancel this by CTRL+C combination anytime." + Environment.NewLine);

            Console.Write("Enter password: ");

            var password = GetPasswords();
            //var charset = Charsets[language] + (useNumbers ? "0123456789" : "") + (useSymbols ? "!@$?_-\"#$/%&()`+*[],;:.^<>" : "");

            var found = false;
            var lastpwd = string.Empty;
            var attempts = 0;
            var maxNumberAttempts = Convert.ToInt32(password.Length * averageCharLength * (password.Length-1) * averageCharLength * (password.Length-2) * averageCharLength);
            var stepSize = (maxNumberAttempts + 101) / 100;


            Console.WriteLine();
            Console.Write($"[{string.Empty, 100}] 0%");

            var sw = new Stopwatch();
            sw.Start();
            foreach(var pwd in GeneratePasswords(password))
            {
                lastpwd = pwd;
                try
                {
                    encryptedSecret.GetKey(pwd);
                    found = true; 
                    break;
                }
                catch (SecurityException)
                {
                }
                Progress(++attempts, stepSize, maxNumberAttempts, sw.Elapsed);
            }
            sw.Stop();

            Console.WriteLine(Environment.NewLine);
            Console.WriteLine($"Completed in {sw.Elapsed}");
            Console.WriteLine(found ? $"SUCCESS: Password found: >>> {lastpwd} <<<" : "FAILED: Password not found");
            Console.WriteLine();
        }

        private static string GetPasswords()
        {
            var stack = new Stack<char>();
            var nextKey = Console.ReadKey(true);

            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (stack.Count > 0)
                    {
                        stack.Pop();
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    stack.Push(nextKey.KeyChar);
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            return new string(stack.Reverse().ToArray());
        }

        private static void Progress(int iter, int stepSize, int max, TimeSpan elapsed)
        {
            if(iter % stepSize == 0)
            {
                var percentage = (int)((float)iter / max * 100);
                var estimatedTime = elapsed / percentage * (100 - percentage);
                var bar = new string('#', percentage);

                Console.CursorLeft = 0;
                Console.Write($"[{bar, -100}] {percentage}% - ET: {estimatedTime}");
            }
        }

        private static void ShowHelp (OptionSet p)
        {
            Console.WriteLine ("Usage: dotnet run [OPTIONS]+");
            Console.WriteLine ("Example: dotnet run -s=\"6PYSeErf23ArQL7xXUWPKa3VBin6cuDaieSdABvVyTA51dS4Mxrtg1CpGN\" -p=\"password\"");
            Console.WriteLine ("Options:");
            p.WriteOptionDescriptions (Console.Out);
        }

        private static IEnumerable<string> GeneratePasswords(string password)
        {
            var pwChar = password.ToCharArray();

            for(var i=0; i < pwChar.Length; i++)
            {
                //Guessing when one error
                var original1 = pwChar[i];
                var charset1 = getCharset(original1]);
                foreach(var c1 in charset1)
                {
                    pwChar[i] = c1;
                    yield return new string(pwChar); 
                }

                //Guessing when two errors
                for(var j=0; j < pwChar.Length; j++){
                    if (j==i) continue;
                    var original2 = pwChar[j];
                    var charset2 = getCharset(original2]);
                    foreach(var c2 in charset2){
                        pwChar[j] = c2;
                        yield return new string(pwChar); 
                    }

                    //Guessing when three errors
                    for(var k=0; k <pwChar.Length;k++){
                        if(k==j | k==i) continue;
                        var original3 = pwChar[k];
                        var charset3 = getCharset(original3]);
                        foreach(var c3 in charset3){
                            pwChar[k] = c3;
                            yield return new string(pwChar); 
                        }
                        //Returning the third character back
                        pwChar[k] = original3;

                    }
                    // Returning the second character back
                    pwChar[j] = original2;

                }
                //Returning the first character back
                pwChar[i] = original1;
            }
        }

        private static string getCharset(char c){
            if (char.isUpper) {return TypoChars[c].ToLower().ToCharArray();}
            else{return TypoChars[c].ToCharArray();}
        } 

        // Failed recursive version. Can't be used with an IEnumberable data type. Maybe modify so it doesn't use one?

        // public static IEnumerable<string> GeneratePasswordsRecursive(char[] password, int depth, List<int> posToSkip){
        //     // // Goes one level deeper than depth value, think of first level as depth 0.
        //     // // pos to skip should be empty initally
        //     // var pwChar = password;
        //     // var posList = posToSkip;
        //     // var skip = false;
        //     // var dep = depth;
        //     // //Console.WriteLine(dep);

        //     // for(var k=0; k <pwChar.Length; k++){
        //     //     skip = false;
        //     //     foreach (var pos in posList){
        //     //         if (k == pos){skip=true;}
        //     //     }
        //     //     if (skip){continue;}

        //     //     var originalChar = pwChar[k];
        //     //     var charset = TypoChars[originalChar].ToCharArray();
        //     //     posList.Add(k);
        //     //     foreach(var c in charset){
        //     //         pwChar[k] = c;

        //     //         yield return new string(pwChar); 
        //     //        // Console.WriteLine("got here");
        //     //         if (dep > 0) {
        //     //             Console.WriteLine(dep);
        //     //             yield return GeneratePasswordsRecursive(pwChar,dep-1,posList);
        //     //             }
        //     //         //Console.WriteLine("made it ");
        //     //     }

        //         // //Returning the character back
        //         // pwChar[k] = originalChar;
        //         // // Added the extra possiblities
        //         // if ((k == 4) ^ (k == 11) ^ (k == 13)){
        //         //     var tempStr = new string(pwChar);
        //         //     tempStr.Insert(k," ");
        //         //     posList.RemoveAt(posList.Count() -1);
        //         //     posList.Add(k+1);
        //         //     yield return tempStr;
        //         //     if (dep > 0){ var result = GeneratePasswordsRecursive(pwChar,dep-1,posList);}
        //         // }else if (k == 12){
        //         //     var tempStr = new string(pwChar);
        //         //     tempStr.Insert(k,".");
        //         //     Console.WriteLine(tempStr);
        //         //     yield return tempStr;
        //         //     if (dep > 0){var result = GeneratePasswordsRecursive(pwChar,dep-1,posList);}
        //         //     tempStr.Remove(k,2);
        //         // }
        //         // posList.RemoveAt(posList.Count() -1);
                
        //     }
        // }

        // private string generatePassword(char[] password, int depth, List<int> posToSkip){
        //     // This needs to be where all the recursion happens so Generate Passwords Recursive can yield return strings

        //     var pwChar = password;
        //     var posList = posToSkip;
        //     var skip = false;
        //     var dep = depth;
        //     //Console.WriteLine(dep);

        //     for(var k=0; k <pwChar.Length; k++){
        //         skip = false;
        //         foreach (var pos in posList){
        //             if (k == pos){skip=true;}
        //         }
        //         if (skip){continue;}

        //         var originalChar = pwChar[k];
        //         var charset = TypoChars[originalChar].ToCharArray();
        //         posList.Add(k);
        //         foreach(var c in charset){
        //             pwChar[k] = c;

        //             yield return new string(pwChar); 
        //            // Console.WriteLine("got here");
        //             if (dep > 0) {
        //                 Console.WriteLine(dep);
        //                 return GeneratePasswordsRecursive(pwChar,dep-1,posList);
        //                 }
        //             //Console.WriteLine("made it ");
        //         }
        //         posList.RemoveAt(posList.Count() -1);
        //     }
        // }
    }
}
