using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

// Set a variable to the Documents path.
string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
Console.WriteLine("Do you want to Encrypt or Decrypt? (E/D)" );
string? enteredText = Console.ReadLine();
switch (enteredText)

{
    case "E":
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("What do you want to encrypt?");
        string? encryptText = Console.ReadLine();
        Console.WriteLine("input password");
        string? password = Console.ReadLine();
    
        // generate a random number key
        var salt = new byte[32];
        var key = new byte[16];
        RandomNumberGenerator.Fill(salt);
        

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256);
        key = pbkdf2.GetBytes(32);
        
        using var aes = new AesGcm(key);
        
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
        RandomNumberGenerator.Fill(nonce);
    
        // Encrypts the text using the random number key
        var plaintextBytes = Encoding.UTF8.GetBytes(encryptText);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
    
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        

        // Write the specified text asynchronously to a new file named "Secret.txt".
        using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "Secret.txt")))
        {  
            await outputFile.WriteAsync(Convert.ToBase64String(nonce));
            await outputFile.WriteAsync(" | ");
            await outputFile.WriteAsync(Convert.ToBase64String(ciphertext));
            await outputFile.WriteAsync(" | ");
            await outputFile.WriteAsync(Convert.ToBase64String(tag));
            await outputFile.WriteAsync(" | ");
            await outputFile.WriteAsync(Convert.ToBase64String(salt));
            
            
            Console.WriteLine("it worked i think!");
        }
        break;
    }
    case "D":
    {
        Console.WriteLine("input password");
        string? password2 = Console.ReadLine();
        using var sr = new StreamReader(Path.Combine(docPath, "Secret.txt"));
        var fileContent = sr.ReadToEnd();
        var fileContentArray = fileContent.Split(" | ");
        var nonce = Convert.FromBase64String(fileContentArray[0]);
        var cipertext = Convert.FromBase64String(fileContentArray[1]);
        var tag = Convert.FromBase64String(fileContentArray[2]);
        var salt = Convert.FromBase64String(fileContentArray[3]);
        var key = new byte[32];

        using var pbkdf2 = new Rfc2898DeriveBytes(password2, salt, 600000, HashAlgorithmName.SHA256);
        key = pbkdf2.GetBytes(32);

        using var aes = new AesCcm(key);
        var plaintextBytes = new byte[cipertext.Length];
        aes.Decrypt(nonce,cipertext,tag, plaintextBytes);
        Console.WriteLine("It worked i think!");
        Console.WriteLine(plaintextBytes);
        break;
    }
}
