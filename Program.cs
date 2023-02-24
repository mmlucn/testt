using MCProxy;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;


namespace MinecraftProxyServer
{
    class Program
    {
        static void Main(string[] args)
        {
            // Load the private key of the Minecraft server
            RSAParameters serverPrivateKey = LoadPrivateKeyFromFile("private.pem");

            // Connect to the Minecraft client
            TcpListener listener = new TcpListener(IPAddress.Any, 25566);
            listener.Start();
            TcpClient client = listener.AcceptTcpClient();
            NetworkStream clientStream = client.GetStream();

            // If the client connected, we can now connect to the Minecraft server
            TcpClient server = new TcpClient("188.40.83.167", 35596);
            NetworkStream serverStream = server.GetStream();

            // Start proxying packets between the client and the server
            while (true)
            {
                // Check if the client has data to send
                if (clientStream.DataAvailable)
                {
                    // Read the packet from the client
                    byte[] clientPacket = ReadPacketFromStream(clientStream);

                    // If this is a handshake packet, replace the server address and port with our own
                    if (clientPacket[0] == 0x00)
                    {
                        // Modify the packet to use our own server address and port
                        clientPacket = ModifyHandshakePacket(clientPacket);
                    }

                    // If this is an encryption response packet, decrypt the shared secret and nonce
                    if (clientPacket[0] == 0x01)
                    {
                        // Decrypt the shared secret and nonce
                        clientPacket = DecryptEncryptionResponsePacket(clientPacket, serverPrivateKey);
                    }

                    // Send the packet to the server
                    serverStream.Write(clientPacket, 0, clientPacket.Length);
                }

                // Check if the server has data to send
                if (serverStream.DataAvailable)
                {
                    // Read the packet from the server
                    byte[] serverPacket = ReadPacketFromStream(serverStream);

                    // If this is a set compression packet, modify the packet to disable compression
                    if (serverPacket[0] == 0x03)
                    {
                        serverPacket = ModifySetCompressionPacket(serverPacket, false);
                    }

                    // Send the packet to the client
                    clientStream.Write(serverPacket, 0, serverPacket.Length);
                }
            }
        }


        private static byte[] ModifyHandshakePacket(byte[] packet)
        {
            MemoryStream stream = new MemoryStream(packet);
            BinaryReader reader = new BinaryReader(stream);
            byte protocolVersion = reader.ReadByte();
            byte[] serverAddress = ReadVarIntPrefixedByteArray(packet, 1 + 1);
            ushort serverPort = reader.ReadUInt16();
            byte nextState = reader.ReadByte();

            // Replace the server address and port with our own
            byte[] newServerAddress = Encoding.ASCII.GetBytes("localhost");
            byte[] newServerPort = BitConverter.GetBytes((ushort)25565);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(newServerPort);
            }

            MemoryStream newStream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(newStream);

            writer.Write(new VarInt(protocolVersion, 1));
            writer.Write(new VarInt(newServerAddress.Length, 1));
            writer.Write(newServerAddress);
            writer.Write(newServerPort);
            writer.Write(nextState);

            return newStream.ToArray();
        }

        private static byte[] DecryptEncryptionResponsePacket(byte[] packet, RSAParameters serverPrivateKey)
        {
            byte[] sharedSecret = ReadVarIntPrefixedByteArray(packet, 1);
            byte[] nonce = ReadVarIntPrefixedByteArray(packet, 1 + sharedSecret.Length);

            sharedSecret = DecryptData(sharedSecret, serverPrivateKey.Modulus, serverPrivateKey.Exponent);
            nonce = DecryptData(nonce, serverPrivateKey.Modulus, serverPrivateKey.Exponent);

            // Re-encrypt the shared secret and nonce using AES-CFB8
            byte[] encryptedSharedSecret = EncryptData(sharedSecret, nonce);
            byte[] encryptedNonce = EncryptData(nonce, nonce);

            // Replace the shared secret and nonce in the packet
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new VarInt(encryptedSharedSecret.Length, 1));
            writer.Write(encryptedSharedSecret);
            writer.Write(new VarInt(encryptedNonce.Length, 1));
            writer.Write(encryptedNonce);

            return stream.ToArray();
        }

        private static byte[] ModifySetCompressionPacket(byte[] packet, bool enableCompression)
        {
            // Create a new stream to modify the packet
            MemoryStream newPacketStream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(newPacketStream);

            // Read the packet ID
            byte packetId = packet[0];
            writer.Write(packetId);

            // If the packet is the set compression packet, modify the threshold value
            if (packetId == 0x03)
            {
                // If compression is disabled, set the threshold to -1
                int threshold = enableCompression ? 256 : -1;

                // Write the modified threshold value to the new packet stream
                VarInt.WriteVarInt(writer, threshold);
            }
            else
            {
                // If the packet is not the set compression packet, write the packet data as-is
                writer.Write(packet, 1, packet.Length - 1);
            }

            // Get the modified packet data from the new packet stream
            byte[] newPacket = newPacketStream.ToArray();

            return newPacket;
        }


        static byte[] ReadPacketFromStream(Stream stream)
        {
            VarInt length = ReadVarIntFromStream(stream);
            byte[] data = new byte[length];
            int bytesRead = 0;

            while (bytesRead < length)
            {
                int bytesToRead = length - bytesRead;
                int n = stream.Read(data, bytesRead, bytesToRead);
                if (n == 0)
                {
                    throw new EndOfStreamException("End of stream reached before packet could be fully read.");
                }
                bytesRead += n;
            }

            return data;
        }
        static VarInt ReadVarIntFromStream(Stream stream)
        {
            int numRead = 0;
            int result = 0;
            byte read;
            do
            {
                int b = stream.ReadByte();
                if (b == -1)
                {
                    throw new EndOfStreamException("End of stream reached before VarInt could be fully read.");
                }
                read = (byte)b;
                int value = (read & 0b01111111);
                result |= (value << (7 * numRead));

                numRead++;
                if (numRead > 5)
                {
                    throw new InvalidOperationException("VarInt is too big");
                }
            } while ((read & 0b10000000) != 0);

            return new VarInt(result, numRead);
        }
        static byte[] EncryptData(byte[] data, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CFB;
                aes.Padding = PaddingMode.None;

                using (MemoryStream stream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                    }

                    return stream.ToArray();
                }
            }
        }
        static byte[] DecryptData(byte[] data, byte[] key, byte[] nonce)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = nonce;
                aes.Mode = CipherMode.CFB;
                aes.Padding = PaddingMode.None;

                using (MemoryStream stream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                    }

                    return stream.ToArray();
                }
            }
        }
        static byte[] ReadVarIntPrefixedByteArray(byte[] data, int startIndex)
        {
            VarInt length = ReadVarInt(data, startIndex);
            byte[] result = new byte[length];
            Array.Copy(data, startIndex + length.Size, result, 0, length);
            return result;
        }
        static VarInt ReadVarInt(byte[] data, int startIndex)
        {
            int numRead = 0;
            int result = 0;
            byte read;
            do
            {
                read = data[startIndex + numRead];
                int value = (read & 0b01111111);
                result |= (value << (7 * numRead));

                numRead++;
                if (numRead > 5)
                {
                    throw new InvalidOperationException("VarInt is too big");
                }
            } while ((read & 0b10000000) != 0);

            return new VarInt(result, numRead);
        }
        static RSAParameters LoadPrivateKeyFromFile(string privateKeyFilePath)
        {
            string privateKeyPem = File.ReadAllText(privateKeyFilePath);
            string base64PrivateKey = privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "")
                                                   .Replace("-----END PRIVATE KEY-----", "")
                                                   .Replace("\n", "");

            byte[] privateKeyBytes = Convert.FromBase64String(base64PrivateKey);
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            return rsa.ExportParameters(true);
        }
    }

}

