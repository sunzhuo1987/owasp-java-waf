//
// In order to convert some functionality to Visual C#, the Java Language Conversion Assistant
// creates "support classes" that duplicate the original functionality.  
//
// Support classes replicate the functionality of the original code, but in some cases they are 
// substantially different architecturally. Although every effort is made to preserve the 
// original architecture of the application in the converted project, the user should be aware that 
// the primary goal of these support classes is to replicate functionality, and that at times 
// the architecture of the resulting solution may differ somewhat.
//

using System;

	/// <summary>
	/// This interface should be implemented by any class whose instances are intended 
	/// to be executed by a thread.
	/// </summary>
	public interface IThreadRunnable
	{
		/// <summary>
		/// This method has to be implemented in order that starting of the thread causes the object's 
		/// run method to be called in that separately executing thread.
		/// </summary>
		void Run();
	}

/// <summary>
/// Contains conversion support elements such as classes, interfaces and static methods.
/// </summary>
public class SupportClass
{
	/// <summary>
	/// Represents a collection ob objects that contains no duplicate elements.
	/// </summary>	
	public interface SetSupport : System.Collections.ICollection, System.Collections.IList
	{
		/// <summary>
		/// Adds a new element to the Collection if it is not already present.
		/// </summary>
		/// <param name="obj">The object to add to the collection.</param>
		/// <returns>Returns true if the object was added to the collection, otherwise false.</returns>
		new bool Add(System.Object obj);

		/// <summary>
		/// Adds all the elements of the specified collection to the Set.
		/// </summary>
		/// <param name="c">Collection of objects to add.</param>
		/// <returns>true</returns>
		bool AddAll(System.Collections.ICollection c);
	}


	/*******************************/
	/// <summary>
	/// Converts the specified collection to its string representation.
	/// </summary>
	/// <param name="c">The collection to convert to string.</param>
	/// <returns>A string representation of the specified collection.</returns>
	public static System.String CollectionToString(System.Collections.ICollection c)
	{
		System.Text.StringBuilder s = new System.Text.StringBuilder();
		
		if (c != null)
		{
		
			System.Collections.ArrayList l = new System.Collections.ArrayList(c);

			bool isDictionary = (c is System.Collections.BitArray || c is System.Collections.Hashtable || c is System.Collections.IDictionary || c is System.Collections.Specialized.NameValueCollection || (l.Count > 0 && l[0] is System.Collections.DictionaryEntry));
			for (int index = 0; index < l.Count; index++) 
			{
				if (l[index] == null)
					s.Append("null");
				else if (!isDictionary)
					s.Append(l[index]);
				else
				{
					isDictionary = true;
					if (c is System.Collections.Specialized.NameValueCollection)
						s.Append(((System.Collections.Specialized.NameValueCollection)c).GetKey (index));
					else
						s.Append(((System.Collections.DictionaryEntry) l[index]).Key);
					s.Append("=");
					if (c is System.Collections.Specialized.NameValueCollection)
						s.Append(((System.Collections.Specialized.NameValueCollection)c).GetValues(index)[0]);
					else
						s.Append(((System.Collections.DictionaryEntry) l[index]).Value);

				}
				if (index < l.Count - 1)
					s.Append(", ");
			}
			
			if(isDictionary)
			{
				if(c is System.Collections.ArrayList)
					isDictionary = false;
			}
			if (isDictionary)
			{
				s.Insert(0, "{");
				s.Append("}");
			}
			else 
			{
				s.Insert(0, "[");
				s.Append("]");
			}
		}
		else
			s.Insert(0, "null");
		return s.ToString();
	}

	/// <summary>
	/// Tests if the specified object is a collection and converts it to its string representation.
	/// </summary>
	/// <param name="obj">The object to convert to string</param>
	/// <returns>A string representation of the specified object.</returns>
	public static System.String CollectionToString(System.Object obj)
	{
		System.String result = "";

		if (obj != null)
		{
			if (obj is System.Collections.ICollection)
				result = CollectionToString((System.Collections.ICollection)obj);
			else
				result = obj.ToString();
		}
		else
			result = "null";

		return result;
	}
	/*******************************/
	/// <summary>
	/// SupportClass for the HashSet class.
	/// </summary>
	[Serializable]
	public class HashSetSupport : System.Collections.ArrayList, SetSupport
	{
		public HashSetSupport() : base()
		{	
		}

		public HashSetSupport(System.Collections.ICollection c) 
		{
			this.AddAll(c);
		}

		public HashSetSupport(int capacity) : base(capacity)
		{
		}

		/// <summary>
		/// Adds a new element to the ArrayList if it is not already present.
		/// </summary>		
		/// <param name="obj">Element to insert to the ArrayList.</param>
		/// <returns>Returns true if the new element was inserted, false otherwise.</returns>
		new public virtual bool Add(System.Object obj)
		{
			bool inserted;

			if ((inserted = this.Contains(obj)) == false)
			{
				base.Add(obj);
			}

			return !inserted;
		}

		/// <summary>
		/// Adds all the elements of the specified collection that are not present to the list.
		/// </summary>
		/// <param name="c">Collection where the new elements will be added</param>
		/// <returns>Returns true if at least one element was added, false otherwise.</returns>
		public bool AddAll(System.Collections.ICollection c)
		{
			System.Collections.IEnumerator e = new System.Collections.ArrayList(c).GetEnumerator();
			bool added = false;

			while (e.MoveNext() == true)
			{
				if (this.Add(e.Current) == true)
					added = true;
			}

			return added;
		}
		
		/// <summary>
		/// Returns a copy of the HashSet instance.
		/// </summary>		
		/// <returns>Returns a shallow copy of the current HashSet.</returns>
		public override System.Object Clone()
		{
			return base.MemberwiseClone();
		}
	}


	/*******************************/
	/// <summary>
	/// SupportClass for the SortedSet interface.
	/// </summary>
	public interface SortedSetSupport : SetSupport
	{
		/// <summary>
		/// Returns a portion of the list whose elements are less than the limit object parameter.
		/// </summary>
		/// <param name="l">The list where the portion will be extracted.</param>
		/// <param name="limit">The end element of the portion to extract.</param>
		/// <returns>The portion of the collection whose elements are less than the limit object parameter.</returns>
		SortedSetSupport HeadSet(System.Object limit);

		/// <summary>
		/// Returns a portion of the list whose elements are greater that the lowerLimit parameter less than the upperLimit parameter.
		/// </summary>
		/// <param name="l">The list where the portion will be extracted.</param>
		/// <param name="limit">The start element of the portion to extract.</param>
		/// <param name="limit">The end element of the portion to extract.</param>
		/// <returns>The portion of the collection.</returns>
		SortedSetSupport SubSet(System.Object lowerLimit, System.Object upperLimit);

		/// <summary>
		/// Returns a portion of the list whose elements are greater than the limit object parameter.
		/// </summary>
		/// <param name="l">The list where the portion will be extracted.</param>
		/// <param name="limit">The start element of the portion to extract.</param>
		/// <returns>The portion of the collection whose elements are greater than the limit object parameter.</returns>
		SortedSetSupport TailSet(System.Object limit);
	}


	/*******************************/
	/// <summary>
	/// SupportClass for the TreeSet class.
	/// </summary>
	[Serializable]
	public class TreeSetSupport : System.Collections.ArrayList, SetSupport, SortedSetSupport
	{
		private System.Collections.IComparer comparator = System.Collections.Comparer.Default;

		public TreeSetSupport() : base()
		{
		}

		public TreeSetSupport(System.Collections.ICollection c) : base()
		{
			this.AddAll(c);
		}

		public TreeSetSupport(System.Collections.IComparer c) : base()
		{
			this.comparator = c;
		}

		/// <summary>
		/// Gets the IComparator object used to sort this set.
		/// </summary>
		public System.Collections.IComparer Comparator
		{
			get
			{
				return this.comparator;
			}
		}

		/// <summary>
		/// Adds a new element to the ArrayList if it is not already present and sorts the ArrayList.
		/// </summary>
		/// <param name="obj">Element to insert to the ArrayList.</param>
		/// <returns>TRUE if the new element was inserted, FALSE otherwise.</returns>
		new public bool Add(System.Object obj)
		{
			bool inserted;
			if ((inserted = this.Contains(obj)) == false)
			{
				base.Add(obj);
				this.Sort(this.comparator);
			}
			return !inserted;
		}

		/// <summary>
		/// Adds all the elements of the specified collection that are not present to the list.
		/// </summary>		
		/// <param name="c">Collection where the new elements will be added</param>
		/// <returns>Returns true if at least one element was added to the collection.</returns>
		public bool AddAll(System.Collections.ICollection c)
		{
			System.Collections.IEnumerator e = new System.Collections.ArrayList(c).GetEnumerator();
			bool added = false;
			while (e.MoveNext() == true)
			{
				if (this.Add(e.Current) == true)
					added = true;
			}
			this.Sort(this.comparator);
			return added;
		}

		/// <summary>
		/// Determines whether an element is in the the current TreeSetSupport collection. The IComparer defined for 
		/// the current set will be used to make comparisons between the elements already inserted in the collection and 
		/// the item specified.
		/// </summary>
		/// <param name="item">The object to be locatet in the current collection.</param>
		/// <returns>true if item is found in the collection; otherwise, false.</returns>
		public override bool Contains(System.Object item)
		{
			System.Collections.IEnumerator tempEnumerator = this.GetEnumerator();
			while (tempEnumerator.MoveNext())
				if (this.comparator.Compare(tempEnumerator.Current, item) == 0)
					return true;
			return false;
		}

		/// <summary>
		/// Returns a portion of the list whose elements are less than the limit object parameter.
		/// </summary>
		/// <param name="limit">The end element of the portion to extract.</param>
		/// <returns>The portion of the collection whose elements are less than the limit object parameter.</returns>
		public SortedSetSupport HeadSet(System.Object limit)
		{
			SortedSetSupport newList = new TreeSetSupport();
			for (int i = 0; i < this.Count; i++)
			{
				if (this.comparator.Compare(this[i], limit) >= 0)
					break;
				newList.Add(this[i]);
			}
			return newList;
		}

		/// <summary>
		/// Returns a portion of the list whose elements are greater that the lowerLimit parameter less than the upperLimit parameter.
		/// </summary>
		/// <param name="lowerLimit">The start element of the portion to extract.</param>
		/// <param name="upperLimit">The end element of the portion to extract.</param>
		/// <returns>The portion of the collection.</returns>
		public SortedSetSupport SubSet(System.Object lowerLimit, System.Object upperLimit)
		{
			SortedSetSupport newList = new TreeSetSupport();
			int i = 0;
			while (this.comparator.Compare(this[i], lowerLimit) < 0)
				i++;
			for (; i < this.Count; i++)
			{
				if (this.comparator.Compare(this[i], upperLimit) >= 0)
					break;
				newList.Add(this[i]);
			}
			return newList;
		}

		/// <summary>
		/// Returns a portion of the list whose elements are greater than the limit object parameter.
		/// </summary>
		/// <param name="limit">The start element of the portion to extract.</param>
		/// <returns>The portion of the collection whose elements are greater than the limit object parameter.</returns>
		public SortedSetSupport TailSet(System.Object limit)
		{
			SortedSetSupport newList = new TreeSetSupport();
			int i = 0;
			while (this.comparator.Compare(this[i], limit) < 0)
				i++;
			for (; i < this.Count; i++)
				newList.Add(this[i]);
			return newList;
		}
	}


	/*******************************/
	/// <summary>
	/// This class uses a cryptographic Random Number Generator to provide support for
	/// strong pseudo-random number generation.
	/// </summary>
	[Serializable]
	public class SecureRandomSupport : System.Runtime.Serialization.ISerializable
	{
		private System.Security.Cryptography.RNGCryptoServiceProvider generator;

		//Serialization
		public void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
		{
		}

		protected SecureRandomSupport(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
		{
			this.generator = new System.Security.Cryptography.RNGCryptoServiceProvider();
		}

		/// <summary>
		/// Initializes a new instance of the random number generator.
		/// </summary>
		public SecureRandomSupport()
		{
			this.generator = new System.Security.Cryptography.RNGCryptoServiceProvider();
		}

		/// <summary>
		/// Initializes a new instance of the random number generator with the given seed.
		/// </summary>
		/// <param name="seed">The initial seed for the generator</param>
		public SecureRandomSupport(byte[] seed)
		{
			this.generator = new System.Security.Cryptography.RNGCryptoServiceProvider(seed);
		}

		/// <summary>
		/// Returns an array of bytes with a sequence of cryptographically strong random values.
		/// </summary>
		/// <param name="randomnumbersarray">The array of bytes to fill.</param>
		public sbyte[] NextBytes(byte[] randomnumbersarray)
		{
			this.generator.GetBytes(randomnumbersarray);
			return ToSByteArray(randomnumbersarray);
		}

		/// <summary>
		/// Returns the given number of seed bytes generated for the first running of a new instance 
		/// of the random number generator.
		/// </summary>
		/// <param name="numberOfBytes">Number of seed bytes to generate.</param>
		/// <returns>Seed bytes generated</returns>
		public static byte[] GetSeed(int numberOfBytes)
		{
			System.Security.Cryptography.RNGCryptoServiceProvider generatedSeed = new System.Security.Cryptography.RNGCryptoServiceProvider();
			byte[] seeds = new byte[numberOfBytes];
			generatedSeed.GetBytes(seeds);
			return seeds;
		}

		/// <summary>
		/// Returns the given number of seed bytes generated for the first running of a new instance 
		/// of the random number generator.
		/// </summary>
		/// <param name="numberOfBytes">Number of seed bytes to generate.</param>
		/// <returns>Seed bytes generated.</returns>
		public byte[] GenerateSeed(int numberOfBytes)
		{
			System.Security.Cryptography.RNGCryptoServiceProvider generatedSeed = new System.Security.Cryptography.RNGCryptoServiceProvider();
			byte[] seeds = new byte[numberOfBytes];
			generatedSeed.GetBytes(seeds);
			return seeds;
		}

		/// <summary>
		/// Creates a new instance of the random number generator with the seed provided by the user.
		/// </summary>
		/// <param name="newSeed">Seed to create a new random number generator.</param>
		public void SetSeed(byte[] newSeed)
		{
			this.generator = new System.Security.Cryptography.RNGCryptoServiceProvider(newSeed);
		}

		/// <summary>
		/// Creates a new instance of the random number generator with the seed provided by the user.
		/// </summary>
		/// <param name="newSeed">Seed to create a new random number generator.</param>
		public void SetSeed(long newSeed)
		{
			byte[] bytes = new byte[8];
			for (int index = 7; index > 0; index--)
			{
				bytes[index] = (byte) (newSeed - (long) ((newSeed >> 8) << 8));
				newSeed  = (long) (newSeed >> 8);
			}
			SetSeed(bytes);
		}
	}


	/*******************************/
	/// <summary>
	/// Receives a byte array and returns it transformed in an sbyte array
	/// </summary>
	/// <param name="byteArray">Byte array to process</param>
	/// <returns>The transformed array</returns>
	public static sbyte[] ToSByteArray(byte[] byteArray)
	{
		sbyte[] sbyteArray = null;
		if (byteArray != null)
		{
			sbyteArray = new sbyte[byteArray.Length];
			for(int index=0; index < byteArray.Length; index++)
				sbyteArray[index] = (sbyte) byteArray[index];
		}
		return sbyteArray;
	}

	/*******************************/
	/// <summary>
	/// Converts an array of sbytes to an array of bytes
	/// </summary>
	/// <param name="sbyteArray">The array of sbytes to be converted</param>
	/// <returns>The new array of bytes</returns>
	public static byte[] ToByteArray(sbyte[] sbyteArray)
	{
		byte[] byteArray = null;

		if (sbyteArray != null)
		{
			byteArray = new byte[sbyteArray.Length];
			for(int index=0; index < sbyteArray.Length; index++)
				byteArray[index] = (byte) sbyteArray[index];
		}
		return byteArray;
	}

	/// <summary>
	/// Converts a string to an array of bytes
	/// </summary>
	/// <param name="sourceString">The string to be converted</param>
	/// <returns>The new array of bytes</returns>
	public static byte[] ToByteArray(System.String sourceString)
	{
		return System.Text.UTF8Encoding.UTF8.GetBytes(sourceString);
	}

	/// <summary>
	/// Converts a array of object-type instances to a byte-type array.
	/// </summary>
	/// <param name="tempObjectArray">Array to convert.</param>
	/// <returns>An array of byte type elements.</returns>
	public static byte[] ToByteArray(System.Object[] tempObjectArray)
	{
		byte[] byteArray = null;
		if (tempObjectArray != null)
		{
			byteArray = new byte[tempObjectArray.Length];
			for (int index = 0; index < tempObjectArray.Length; index++)
				byteArray[index] = (byte)tempObjectArray[index];
		}
		return byteArray;
	}

	/*******************************/
	/// <summary>
	/// Converts an array of sbytes to an array of chars
	/// </summary>
	/// <param name="sByteArray">The array of sbytes to convert</param>
	/// <returns>The new array of chars</returns>
	public static char[] ToCharArray(sbyte[] sByteArray) 
	{
		return System.Text.UTF8Encoding.UTF8.GetChars(ToByteArray(sByteArray));
	}

	/// <summary>
	/// Converts an array of bytes to an array of chars
	/// </summary>
	/// <param name="byteArray">The array of bytes to convert</param>
	/// <returns>The new array of chars</returns>
	public static char[] ToCharArray(byte[] byteArray) 
	{
		return System.Text.UTF8Encoding.UTF8.GetChars(byteArray);
	}

	/*******************************/
	/// <summary>
	/// This class is a holder for two keys, a private key and a public key.
	/// </summary>
	public class KeyPairSupport
	{
		private PrivateKeySupport privateKey;
		private PublicKeySupport  publicKey;
		
		/// <summary>
		/// Construct a new key pair object with the specified PublicKeySupport and PrivateKeySupport
		/// </summary>
		/// <param name="publicKey">The public key</param>
		/// <param name="privateKey">The private key</param>
		public KeyPairSupport(PublicKeySupport  publicKey, PrivateKeySupport privateKey)
		{
			this.publicKey  = publicKey;
			this.privateKey = privateKey;
		}

		/// <summary>
		/// A reference to the private key component of this key pair
		/// </summary>
		public PrivateKeySupport Private
		{
			get
			{
				return this.privateKey;
			}
		}

		/// <summary>
		/// A reference to the public key component of this key pair
		/// </summary>
		public PublicKeySupport Public
		{
			get
			{
				return this.publicKey;
			}
		}
	}

	/*******************************/
	/// <summary>
	/// This class offers support for all classes that use cryptographic private keys.
	/// </summary>
	public class PrivateKeySupport: KeySupport
	{
		/// <summary>
		/// Construct a new private key object
		/// </summary>
		public PrivateKeySupport()
		{
		}
	}

	/*******************************/
	/// <summary>
	/// This class offers support for all classes that use cryptographic keys.
	/// </summary>
	public class KeySupport
	{
		private System.Security.Cryptography.KeyedHashAlgorithm algorithm;

		/// <summary>
		/// Construct to new objects key
		/// </summary>
		public KeySupport()
		{
		}

		/// <summary>
		/// Construct to new objects key with the algorithm specified
		/// </summary>
		/// <param name="algorithm">the cryptographic algorithm</param>
		public KeySupport(System.Security.Cryptography.KeyedHashAlgorithm algorithm)
		{
			this.algorithm = algorithm;
		}

		/// <summary>
		/// The standard algorithm name for this key
		/// </summary>
		/// <returns>the keyed hash algorithm name</returns>
		public System.String GetAlgorithm()
		{
			return this.algorithm.ToString();
		}		

		/// <summary>
		/// The key to be used in the algorithm.
		/// </summary>
		public byte[] Key
		{
			get
			{
				return this.algorithm.Key;
			}
		}
	}


	/*******************************/
	/// <summary>
	/// This class offers support for all classes that use cryptographic public keys.
	/// </summary>
	public class PublicKeySupport: KeySupport
	{
		/// <summary>
		/// Construct a new public key object
		/// </summary>
		public PublicKeySupport()
		{
		}
	}

	/*******************************/
	/// <summary>
	/// Encapsulates the functionality of message digest algorithms such as SHA-1 or MD5.
	/// </summary>
	public class MessageDigestSupport
	{
		private System.Security.Cryptography.HashAlgorithm algorithm;
		private byte[] data = new byte[0];
		private int position;
		private System.String algorithmName;

		/// <summary>
		/// The HashAlgorithm instance that provide the cryptographic hash algorithm
		/// </summary>
		public System.Security.Cryptography.HashAlgorithm Algorithm
		{
			get
			{
				return this.algorithm;
			}
			set
			{
				this.algorithm  = value;
			}
		}

		/// <summary>
		/// The digest data
		/// </summary>
		public byte[] Data
		{
			get
			{
				return this.data;
			}
			set
			{
				this.data  = value;
			}
		}

		/// <summary>
		/// The name of the cryptographic hash algorithm used in the instance
		/// </summary>
		public System.String AlgorithmName
		{
			get
			{
				return this.algorithmName;
			}
		}

		/// <summary>
		/// Creates a message digest using the specified name to set Algorithm property.
		/// </summary>
		/// <param name="algorithm">The name of the algorithm to use</param>
		public MessageDigestSupport(System.String algorithm)
		{			
			if (algorithm.Equals("SHA-1"))
			{
				this.algorithmName = "SHA";
			}
			else 
			{
				this.algorithmName = algorithm;
			}
			this.Algorithm = (System.Security.Cryptography.HashAlgorithm) System.Security.Cryptography.CryptoConfig.CreateFromName(this.algorithmName);			
			this.data = new byte[0];
			this.position  = 0;
		}

		/// <summary>
		/// Computes the hash value for the internal data digest.
		/// </summary>
		/// <returns>The array of signed bytes with the resulting hash value</returns>
		public sbyte[] DigestData()
		{
			sbyte[] result = ToSByteArray(this.Algorithm.ComputeHash(this.data));
			this.Reset();
			return result;
		}

		/// <summary>
		/// Performs and update on the digest with the specified array and then completes the digest
		/// computation.
		/// </summary>
		/// <param name="newData">The array of bytes for final update to the digest</param>
		/// <returns>An array of signed bytes with the resulting hash value</returns>
		public sbyte[] DigestData(sbyte[] newData)
		{
			this.Update(ToByteArray(newData));
			return this.DigestData();
		}


		/// <summary>
		/// Computes the hash value for the internal digest and places the digest returned into the specified buffer
		/// </summary>
		/// <param name="buff">The buffer for the output digest</param>
		/// <param name="offset">Offset into the buffer for the beginning index</param>
		/// <param name="length">Total number of bytes for the digest</param>
		/// <returns>The number of bytes placed into the output buffer</returns>
		public int DigestData(sbyte[] buffer, int offset, int length)
		{
            	byte[] result = this.Algorithm.ComputeHash(this.data);
			int count = 0;
			if ( length >= this.GetDigestLength() )
			{
				if ( buffer.Length >= (length + offset) )
				{
					for ( ; count < result.Length ; count++ )
					{
						buffer[offset + count] = (sbyte)result[count];						
					}
				}
				else
				{
					throw new System.ArgumentException("output buffer too small for the specified offset and length");
				}
			}
			else
			{
				throw new System.Exception("Partial digests not returned");
			}
			return count;
		}

		/// <summary>
		/// Updates the digest data with the specified array of bytes by making an append
		/// operation in the internal array of data.
		/// </summary>
		/// <param name="newData">The array of bytes for the update operation</param>
		public void Update(byte[] newData)
		{
			if (position == 0)
			{
				this.Data = newData;
				this.position = this.Data.Length - 1;
			}
			else
			{
				byte[] oldData = this.Data;
				this.Data = new byte[newData.Length + position + 1];
				oldData.CopyTo(this.Data, 0);
				newData.CopyTo(this.Data, oldData.Length);
	            
				this.position = this.Data.Length - 1;
			}
		}
        
		/// <summary>
		/// Updates the digest data with the input byte by calling the method Update with an array.
		/// </summary>
		/// <param name="newData">The input byte for the update</param>
		public void Update(byte newData)
		{
			byte[] newDataArray = new byte[1];
			newDataArray[0] = newData;
			this.Update(newDataArray);
		}

		/// <summary>
		/// Updates the specified count of bytes with the input array of bytes starting at the
		/// input offset.
		/// </summary>
		/// <param name="newData">The array of bytes for the update operation</param>
		/// <param name="offset">The initial position to start from in the array of bytes</param>
		/// <param name="count">The number of bytes fot the update</param>
		public void Update(byte[] newData, int offset, int count)
		{
			byte[] newDataArray = new byte[count];
			System.Array.Copy(newData, offset, newDataArray, 0, count);
			this.Update(newDataArray);
		}
		
		/// <summary>
		/// Resets the digest data to the initial state.
		/// </summary>
		public void Reset()
		{
			this.data = null;
			this.position = 0;
		}

		/// <summary>
		/// Returns a string representation of the Message Digest
		/// </summary>
		/// <returns>A string representation of the object</returns>
		public override System.String ToString()
		{
			return this.Algorithm.ToString();
		}

		/// <summary>
		/// Generates a new instance of the MessageDigestSupport class using the specified algorithm
		/// </summary>
		/// <param name="algorithm">The name of the algorithm to use</param>
		/// <returns>A new instance of the MessageDigestSupport class</returns>
		public static MessageDigestSupport GetInstance(System.String algorithm)
		{
			return new MessageDigestSupport(algorithm);
		}
		
		/// <summary>
		/// Compares two arrays of signed bytes evaluating equivalence in digest data
		/// </summary>
		/// <param name="firstDigest">An array of signed bytes for comparison</param>
		/// <param name="secondDigest">An array of signed bytes for comparison</param>
		/// <returns>True if the input digest arrays are equal</returns>
		public static bool EquivalentDigest(System.SByte[] firstDigest, System.SByte[] secondDigest)
		{
			bool result = false;
			if (firstDigest.Length == secondDigest.Length)
			{
				int index = 0;
				result = true;
				while(result && index < firstDigest.Length)
				{
					result = firstDigest[index] == secondDigest[index];
					index++;
				}
			}
			
			return result;
		}


		/// <summary>
		/// Gets a number of bytes representing the length of the digest
		/// </summary>
		/// <returns>The length of the digest in bytes</returns>
		public int GetDigestLength( )
		{
			return this.algorithm.HashSize / 8;
		}
	}
	/*******************************/
	/// <summary>
	/// This class offers support for all classes that use cryptographic classes.
	/// </summary>
	public class CryptoSupport
	{
		// Used for working space to Cipher.
		private System.IO.MemoryStream CipherMemoryStream;

		// Used for key storage to Cipher.
		private System.Security.Cryptography.SymmetricAlgorithm CipherInitKey;

		// The cipher for encrypt and decrypt.
		private System.Security.Cryptography.CryptoStream Cipher;

		// Used for set mode to Cipher
		private System.Security.Cryptography.CryptoStreamMode CipherMode;

		// Used for algorithm name storage to Cipher
		private System.String CipherAlgorithName;

		/// <summary>
		/// Constructor class.
		/// </summary>
		/// <param name="name">The algorithm name input, (for support propose only).</param>
		public CryptoSupport(System.String name)
		{
			CipherInitKey = System.Security.Cryptography.SymmetricAlgorithm.Create();
			CipherAlgorithName = name;
		}

		/// <summary>
		/// Initializes this cipher with the public key from the given certificate.
		/// </summary>
		/// <param name="Mode">The cipher is initialized for one of the following four operations: encryption (Mode = Write) 
		/// or decryption (Mode = Read).</param>
		/// <param name="Certificate">The certificate of type X.509</param>
		public void CryptoInit(System.Security.Cryptography.CryptoStreamMode Mode, System.Security.Cryptography.X509Certificates.X509Certificate Certificate)
		{
			CipherMode = Mode;
			if(CipherInitKey == null) return;
			CipherInitKey.Key = Certificate.GetPublicKey();
		}

		/// <summary>
		/// Initializes this cipher with a key.
		/// </summary>
		/// <param name="Mode">The cipher is initialized for one of the following four operations: encryption (Mode = Write) 
		/// or decryption (Mode = Read).</param>
		/// <param name="Key">The key.</param>	
		public void CryptoInit(System.Security.Cryptography.CryptoStreamMode Mode, System.Object Key)
		{
			CipherMode = Mode;
			if (CipherInitKey == null) return;
			if (Key is System.Security.Cryptography.SymmetricAlgorithm)
				// SecretKeySpec
				CipherInitKey = (System.Security.Cryptography.SymmetricAlgorithm) Key;
			else if ( Key is SupportClass.KeySupport)
				// Security.Key
				CipherInitKey.Key = ((KeySupport) Key).Key;
		}

		/// <summary>
		/// Initializes this cipher with a key and a set of algorithm parameters.
		/// </summary>
		/// <param name="Mode">The cipher is initialized for one of the following four operations: encryption (Mode = Write) 
		/// or decryption (Mode = Read).</param>
		/// <param name="Key">The key.</param>
		/// <param name="Spec">The algorithm parameters.</param>
		public void CryptoInit(System.Security.Cryptography.CryptoStreamMode Mode, System.Object Key, System.Object Spec)
		{
			CipherMode = Mode;
			if (CipherInitKey == null) return;
			if ((Key is System.Security.Cryptography.SymmetricAlgorithm) && (Spec is System.Security.Cryptography.SymmetricAlgorithm))
			{
				// SecretKeySpec
				CipherInitKey.Key = ((System.Security.Cryptography.SymmetricAlgorithm) Key).Key;
				CipherInitKey.IV = ((System.Security.Cryptography.SymmetricAlgorithm) Spec).IV;
			}
			else if ( Key is SupportClass.KeySupport)
				// Security.Key
				CipherInitKey.Key = ((KeySupport) Key).Key;
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
		/// </summary>
		/// <param name="input">The input buffer to encode/decode.</param>
		/// <param name="offset">The offset in input where the input starts.</param>
		/// <param name="count">The input length.</param>
		/// <returns>The encoded/decoded result array of byte.</returns>
		public sbyte[] CryptoDoFinal(sbyte[] input, int offset, int count)
		{
			if (CipherInitKey == null) return new sbyte[0];
			if (CipherMode == System.Security.Cryptography.CryptoStreamMode.Write)
			{
				// Encrypt
				if (CipherMemoryStream != null)
					CipherMemoryStream.Close();
				CipherMemoryStream = new System.IO.MemoryStream();
				Cipher = new System.Security.Cryptography.CryptoStream(CipherMemoryStream, CipherInitKey.CreateEncryptor(), CipherMode);
				Cipher.Write(ToByteArray(input), offset, count);
				Cipher.FlushFinalBlock();
				return ToSByteArray(CipherMemoryStream.ToArray());
			}
			else if ((CipherMode == System.Security.Cryptography.CryptoStreamMode.Read))
			{
				// Decrypt
				if (CipherMemoryStream != null)
					CipherMemoryStream.Close();
				System.Collections.ArrayList TempListResult = new System.Collections.ArrayList(ToByteArray(input));
				byte[] TempResult = new byte[count];
				TempListResult.GetRange(offset, count).CopyTo(TempResult);
				CipherMemoryStream = new System.IO.MemoryStream(TempResult);
				Cipher = new System.Security.Cryptography.CryptoStream(CipherMemoryStream, CipherInitKey.CreateDecryptor(), CipherMode);
				byte[] TempDecode = new byte[TempResult.Length];
				Cipher.Read(TempDecode, 0, TempDecode.Length);

				// Copy only data, not final zero values 
				TempListResult = new System.Collections.ArrayList(TempDecode);
				int indexZero = TempListResult.IndexOf(new byte());
				if (indexZero > 0)
				{
					byte[] DecodeResult = new byte[indexZero];
					for (int i = 0; i<indexZero; i++)
						DecodeResult[i] = TempDecode[i];
					return ToSByteArray(DecodeResult);
				}
				else
					return ToSByteArray(TempDecode);
			}
			else
				return new sbyte[0];
		}

		/// <summary>
		/// Finishes a multiple-part encryption or decryption operation.
		/// </summary>
		/// <param name="output">The buffer for the result to encode/decode.</param>
		/// <param name="offset">The offset in output where the result is stored.</param>
		/// <returns>The number of bytes stored in output.</returns>
		public int CryptoDoFinal(sbyte[] output, int offset)
		{
			if (CipherInitKey == null) return -1;
			if (CipherMode == System.Security.Cryptography.CryptoStreamMode.Write)
			{
				// Encrypt
				byte[] TempOutput = new byte[CipherMemoryStream.Length];
				CipherMemoryStream.ToArray().CopyTo(TempOutput, offset);
				if ((output != null) && (output.Length >= TempOutput.Length))
					ToSByteArray(TempOutput).CopyTo(output,0);
				else
					output = ToSByteArray(TempOutput);
				return TempOutput.Length;
			}
			else if ((CipherMode == System.Security.Cryptography.CryptoStreamMode.Read))
			{
				// Decrypt
				byte[] TempDecode = new byte[CipherMemoryStream.Length];
				CipherMemoryStream = new System.IO.MemoryStream(CipherMemoryStream.ToArray());
				Cipher = new System.Security.Cryptography.CryptoStream(CipherMemoryStream, CipherInitKey.CreateDecryptor(), CipherMode);
				Cipher.Read(TempDecode, 0, TempDecode.Length);
				byte[] TempOutput = new byte[TempDecode.Length];
				TempDecode.CopyTo(TempOutput, offset);
				if ((output != null) && (output.Length >= TempOutput.Length))
					ToSByteArray(TempOutput).CopyTo(output,0);
				else
					output = ToSByteArray(TempOutput);
				return TempOutput.Length;
			}
			else
				return 0;
		}

		/// <summary>
		/// Finishes a multiple-part encryption or decryption operation.
		/// </summary>
		/// <returns>The encoded/decoded result array of byte.</returns>
		public sbyte[] CryptoDoFinal()
		{
			if (CipherInitKey == null) return new sbyte[0];
			if (CipherMode == System.Security.Cryptography.CryptoStreamMode.Write)
				// Encrypt
				return ToSByteArray(CipherMemoryStream.ToArray());
			else if ((CipherMode == System.Security.Cryptography.CryptoStreamMode.Read))
			{
				// Decrypt
				byte [] TempDecode = new byte[CipherMemoryStream.Length];
				CipherMemoryStream = new System.IO.MemoryStream(CipherMemoryStream.ToArray());
				Cipher = new System.Security.Cryptography.CryptoStream(CipherMemoryStream, CipherInitKey.CreateDecryptor(), CipherMode);
				Cipher.Read(TempDecode, 0, TempDecode.Length);
				return ToSByteArray(TempDecode);
			}
			else
				return new sbyte[0];
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <returns>The new buffer with the result.</returns>
		public sbyte[] CryptoDoFinal(sbyte[] input)
		{
			return CryptoDoFinal(input, 0, input.Length);
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <param name="offset">The offset in input where the input starts.</param>
		/// <param name="count">The input length.</param>
		/// <param name="output">The buffer for the result to encode/decode.</param>
		/// <returns>The number of bytes stored in output.</returns>
		public int CryptoDoFinal(sbyte[] input, int offset, int count, sbyte[] output)
		{
			sbyte[] tempResult = CryptoDoFinal(input, offset, count);
			tempResult.CopyTo(output,0);
			return tempResult.Length;
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <param name="offset">The offset in input where the input starts.</param>
		/// <param name="count">The input length.</param>
		/// <param name="output">The buffer for the result to encode/decode.</param>
		/// <param name="outoutOffset">The offset in output where the result is stored.</param>
		/// <returns>The number of bytes stored in output.</returns>
		public int CryptoDoFinal(sbyte[] input, int offset, int count, sbyte[] output, int outputOffset)
		{
			if (outputOffset == 0)
				return CryptoDoFinal(input, offset, count, output);
			else
			{
				sbyte[] TempOutput = CryptoDoFinal(input, offset, count);
				TempOutput.CopyTo(output, outputOffset);
				return TempOutput.Length;
			}
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation, processing another data part.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <returns>The new buffer with the result.</returns>
		public sbyte[] CryptoUpdate (sbyte[] input)
		{
			return ((input == null) || (input.Length == 0)) ? null : CryptoDoFinal(input);
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation, processing another data part.
		/// </summary>
		/// <param name="input">The input buffer to encode/decode.</param>
		/// <param name="offset">The offset in input where the input starts.</param>
		/// <param name="count">The input length.</param>
		/// <returns>The encoded/decoded result array of byte.</returns>
		public sbyte[] CryptoUpdate (sbyte[] input, int offset, int count)
		{
			return (count == 0) ? null : CryptoDoFinal(input, offset, count);
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation, processing another data part.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <param name="offset">The offset in input where the input starts.</param>
		/// <param name="count">The input length.</param>
		/// <param name="output">The buffer for the result to encode/decode.</param>
		/// <returns>The number of bytes stored in output.</returns>
		public int CryptoUpdate (sbyte [] input, int offset, int count, sbyte[] output)
		{
			return (count == 0) ? 0 : CryptoDoFinal(input, offset, count, output);
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation, processing another data part.
		/// </summary>
		/// <param name="input">The input buffer.</param>
		/// <param name="offset">The offset in input where the input starts.</param>
		/// <param name="count">The input length.</param>
		/// <param name="output">The buffer for the result to encode/decode.</param>
		/// <param name="offsetOutput">The offset in output where the result is stored.</param>
		/// <returns>The number of bytes stored in output.</returns>
		public int CryptoUpdate (sbyte [] input, int offset, int count, sbyte[] output, int offsetOutput)
		{
			return (count == 0) ? 0 : CryptoDoFinal(input, offset, count, output, offsetOutput);
		}

		/// <summary>
		/// Returns the algorithm name of this Cipher object.
		/// </summary>
		/// <returns>The algorithm name of this Cipher object.</returns>
		public System.String CryptoGetAlgorithm()
		{
			return CipherAlgorithName;
		}

		/// <summary>
		/// Returns the initialization vector (IV) in a new buffer.
		/// </summary>
		/// <returns>The initialization vector in a new buffer.</returns>
		public sbyte[] CryptoGetIV()
		{
			return (CipherInitKey != null) ? ToSByteArray(CipherInitKey.IV) : null;
		}

		/// <summary>
		/// Returns the block size (in bytes).
		/// </summary>
		/// <returns>the block size (in bytes).</returns>
		public int CryptoGetBlockSize()
		{
			return (CipherInitKey != null) ? CipherInitKey.BlockSize : -1;
		}

		/// <summary>
		/// Returns the length in bytes that an output buffer would need to be in order to hold the result.
		/// </summary>
		/// <returns>the required output buffer size (in bytes)</returns>
		public int CryptoGetOutputSize()
		{
			return CipherInitKey.FeedbackSize/8;
		}

		/// <summary>
		/// Returns the key of cipher.
		/// </summary>
		/// <returns>the cipher key (in sbytes)</returns>
		public sbyte[] CryptoGetEncoded()
		{
			return (CipherInitKey != null) ? ToSByteArray(CipherInitKey.Key) : new sbyte[0];
		}		

		/// <summary>
		/// Creates a clone of the SymmetricAlgorithm object (parameter).
		/// </summary>
		/// <param name="key">The original object that will be cloned.</param>
		/// <returns>Returns the new object.</returns>
		public static System.Security.Cryptography.SymmetricAlgorithm Clone(System.Security.Cryptography.SymmetricAlgorithm key)
		{
			if(key == null) return null;
			System.Security.Cryptography.SymmetricAlgorithm tempKey = System.Security.Cryptography.SymmetricAlgorithm.Create(key.GetType().ToString());
			key.GenerateKey();
			tempKey.Key = key.Key;
			return tempKey; 
		}

		/// <summary>
		/// Support function to constructs a "SealedObject" from any serializable object.
		/// </summary>
		/// <param name="obj">The object to be sealed.</param>
		/// <param name="cipher">The cipher used to seal the object.</param>
		/// <returns>Returns the new cryptography result object.</returns>
		public static System.Object CreateSealedObject(System.Object obj, CryptoSupport cipher)
		{
			System.IO.MemoryStream stream = new System.IO.MemoryStream();
			System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter =
				new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
			formatter.Serialize(stream, obj);
			sbyte[] tempResult = cipher.CryptoDoFinal(ToSByteArray(stream.GetBuffer()));
			return tempResult;			
		}

		/// <summary>
		/// Support function to retrieves the original (encapsulated) object.
		/// </summary>
		/// <param name="obj">The object to be unsealed.</param>
		/// <param name="cipher">The cipher used to unseal the object.</param>
		/// <returns>Returns the new cryptography result object.</returns>
		public static object GetSealedObject(System.Object obj, CryptoSupport cipher)
		{
			sbyte[] buffer = (sbyte[])obj;
			System.IO.MemoryStream stream = new System.IO.MemoryStream(ToByteArray(cipher.CryptoDoFinal(buffer)));
			System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter =
				new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
			return formatter.Deserialize(stream);
		}

		/// <summary>
		/// Support function to retrieves the original (encapsulated) object.
		/// </summary>
		/// <param name="obj">The object to be unsealed.</param>
		/// <param name="key">The the key used to unseal the object.</param>
		/// <returns>Returns the new cryptography result object.</returns>
		public static object GetSealedObject(System.Object obj, System.Object key)
		{
			CryptoSupport cipher = new CryptoSupport("");
			cipher.CryptoInit(System.Security.Cryptography.CryptoStreamMode.Read, key);
			sbyte[] buffer = (sbyte[])obj;
			System.IO.MemoryStream stream = new System.IO.MemoryStream(ToByteArray(cipher.CryptoDoFinal(buffer)));
			System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter =
				new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
			return formatter.Deserialize(stream);
		}
	}


	/*******************************/
	/// <summary>
	/// Support for digital signatures
	/// </summary>
	public class DigitalSignature
	{
		private System.Security.Cryptography.AsymmetricSignatureFormatter formatter;
		private System.Security.Cryptography.AsymmetricSignatureDeformatter deformatter;
		private System.Security.Cryptography.HashAlgorithm hashAlgorithm;
		private int objective;
		private System.String algorithmName;
		private byte[] data;
		private int position;

		public static int SIGN = 1;
		public static int VERIFY = 2;
		

		/// <summary>
		/// Gets or sets the data to be signed
		/// </summary>
		public byte[] Data
		{
			get
			{
				return this.data;
			}
			set
			{
				this.data  = value;
			}
		}

		/// <summary>
		/// Gets the name of the cryptographic algorithm used in the instance
		/// </summary>
		public System.String AlgorithmName
		{
			get
			{
				return this.algorithmName;
			}
		}		

		/// <summary>
		///  Creates a new DigitalSignature object
		/// </summary>
		public DigitalSignature()
		{			
			this.formatter = new System.Security.Cryptography.DSASignatureFormatter();
			this.deformatter = new System.Security.Cryptography.DSASignatureDeformatter();
		}

		/// <summary>
		/// Generates a DigitalSignature instance with the specified algorithm
		/// </summary>
		/// <param name="algorithmName">Name of the algorithm for the new DigitalSignature instance</param>
		/// <returns>The new DigitalSignature instance</returns>
		public static DigitalSignature GetInstance(String algorithmName)
		{
			DigitalSignature signature = null;
			if (algorithmName.ToLower().Equals("sha1withdsa") || algorithmName.ToLower().Equals("shawithdsa"))
			{
				signature = new DigitalSignature();
				System.Security.Cryptography.DSACryptoServiceProvider dsacryptoserviceprovider = new System.Security.Cryptography.DSACryptoServiceProvider();
				signature.formatter = new System.Security.Cryptography.DSASignatureFormatter( dsacryptoserviceprovider );
				signature.deformatter = new System.Security.Cryptography.DSASignatureDeformatter( dsacryptoserviceprovider );				
				signature.hashAlgorithm = new System.Security.Cryptography.SHA1Managed();
				signature.algorithmName = "SHAwithDSA";
				signature.objective = 0;
			}
			else 
			{
				throw new System.Exception("Algorithm not supported");
			}
			return signature;
		}

		/// <summary>
		/// Sets the objective property to specify that the signature was created for signing
		/// </summary>
		public void Signing()
		{
			this.objective = 1;
		}

		/// <summary>
		/// Sets the objetive property to specify that the signature was created for verification
		/// </summary>
		public void Verification()
		{
			this.objective = 2;
		}

		/// <summary>
		/// Creates a signature from the updated data
		/// </summary>
		/// <returns>Signature bytes of the signing operation's result</returns>
		public byte[] Sign()
		{
			byte[] realSignature = null;
			if (this.objective == 1)
				realSignature = this.formatter.CreateSignature(this.Data);
			else
				throw new System.Exception("Object was not created for signing");
			this.Reset();
			return realSignature;
		}		

		/// <summary>
		/// Creates a signature from the updated data and place the result in the output
		/// buffer starting at offset.
		/// </summary>
		/// <param name="outBuffer">Signature result buffer</param>
		/// <param name="offset">Offset into outBuffer where the signature is stored</param>
		/// <param name="lenght">Number of bytes within outBuffer allotted for the signature.</param>
		/// <returns>Number of bytes placed into outBuffer</returns>
		public int Sign( byte[] outBuffer, int offset, int lenght )
		{
			byte[] realSignature = null;
			if (this.objective == 1)
				realSignature = this.formatter.CreateSignature(this.Data);
			else
				throw new System.Exception("Object was not created for signing");
			
			if ( realSignature.Length > lenght )
				throw new System.Exception("Parameter is less than the actual signature length");
			else
				this.Reset();

			return realSignature.Length;
		}

		/// <summary>
		/// Verifies the given signature with the updated data
		/// </summary>
		/// <param name="signature">Signature bytes to be verified</param>
		/// <returns>True if the signature was verified, otherwise false</returns>
		public bool Verify(byte[] signature)
		{
			bool result = false;
			if (this.objective == 2)
				result = this.deformatter.VerifySignature(this.Data, signature);
			else
				throw new System.Exception("Object was not created for verification");
			this.Reset();
			return result;
		}

		/// <summary>
		/// Updates the data with the specified array of bytes
		/// </summary>
		/// <param name="newData">The array of bytes to update the data with</param>
		public void Update(byte[] newData)
		{
			if (this.position == 0)
			{
				this.Data = newData;
				this.hashAlgorithm.TransformBlock(newData, 0, newData.Length, this.Data, 0);
				this.position = this.Data.Length - 1;
			}
			else
			{
				byte[] oldData = this.Data;
				this.Data = new byte[newData.Length + this.position + 1];
				oldData.CopyTo(this.Data, 0);
				byte[] hashedNew = newData;
				this.hashAlgorithm.TransformBlock(newData, 0, hashedNew.Length, hashedNew, 0);
				hashedNew.CopyTo(this.Data, oldData.Length);
				this.position = this.Data.Length - 1;
			}
		}
        
		/// <summary>
		/// Updates the data with the specified byte
		/// </summary>
		/// <param name="newData">The byte to update the data with</param>
		public void Update(byte newData)
		{
			byte[] newDataArray = new byte[1];
			newDataArray[0] = newData;
			this.Update(newDataArray);
		}

		/// <summary>
		/// Updates the data with a part of the specified array of bytes 
		/// </summary>
		/// <param name="newData">The array of bytes containing the part of bytes to update the data with</param>
		/// <param name="offset">The initial position of the part of bytes of the array of bytes</param>
		/// <param name="count">The number of bytes of the part of bytes</param>
		public void Update(byte[] newData, int offset, int count)
		{
			byte[] newDataArray = new byte[count];
			System.Array.Copy(newData, offset, newDataArray, 0, count);
			this.Update(newDataArray);
		}

		/// <summary>
		/// Resets the data to the initial state
		/// </summary>
		private void Reset()
		{
			this.data = null;
			this.position = 0;
		}

		/// <summary>
		/// String representation of the digital signature object
		/// </summary>
		/// <returns>String representation of the signature</returns>
		public override System.String ToString()
		{
			System.String result= "Instance of DigitalSignature for ";
			if (this.objective == 1)
				result += "signing ";
			else
				result += "verification ";
			result += "using " + this.AlgorithmName + " algorithm";
			return result;
		}
	}
	/*******************************/
	/// <summary>
	/// This class provides functionality not found in .NET collection-related interfaces.
	/// </summary>
	public class ICollectionSupport
	{
		/// <summary>
		/// Adds a new element to the specified collection.
		/// </summary>
		/// <param name="c">Collection where the new element will be added.</param>
		/// <param name="obj">Object to add.</param>
		/// <returns>true</returns>
		public static bool Add(System.Collections.ICollection c, System.Object obj)
		{
			bool added = false;
			//Reflection. Invoke either the "add" or "Add" method.
			System.Reflection.MethodInfo method;
			try
			{
				//Get the "add" method for proprietary classes
				method = c.GetType().GetMethod("Add");
				if (method == null)
					method = c.GetType().GetMethod("add");
				int index = (int) method.Invoke(c, new System.Object[] {obj});
				if (index >=0)	
					added = true;
			}
			catch (System.Exception e)
			{
				throw e;
			}
			return added;
		}

		/// <summary>
		/// Adds all of the elements of the "c" collection to the "target" collection.
		/// </summary>
		/// <param name="target">Collection where the new elements will be added.</param>
		/// <param name="c">Collection whose elements will be added.</param>
		/// <returns>Returns true if at least one element was added, false otherwise.</returns>
		public static bool AddAll(System.Collections.ICollection target, System.Collections.ICollection c)
		{
			System.Collections.IEnumerator e = new System.Collections.ArrayList(c).GetEnumerator();
			bool added = false;

			//Reflection. Invoke "addAll" method for proprietary classes
			System.Reflection.MethodInfo method;
			try
			{
				method = target.GetType().GetMethod("addAll");

				if (method != null)
					added = (bool) method.Invoke(target, new System.Object[] {c});
				else
				{
					method = target.GetType().GetMethod("Add");
					while (e.MoveNext() == true)
					{
						bool tempBAdded =  (int) method.Invoke(target, new System.Object[] {e.Current}) >= 0;
						added = added ? added : tempBAdded;
					}
				}
			}
			catch (System.Exception ex)
			{
				throw ex;
			}
			return added;
		}

		/// <summary>
		/// Removes all the elements from the collection.
		/// </summary>
		/// <param name="c">The collection to remove elements.</param>
		public static void Clear(System.Collections.ICollection c)
		{
			//Reflection. Invoke "Clear" method or "clear" method for proprietary classes
			System.Reflection.MethodInfo method;
			try
			{
				method = c.GetType().GetMethod("Clear");

				if (method == null)
					method = c.GetType().GetMethod("clear");

				method.Invoke(c, new System.Object[] {});
			}
			catch (System.Exception e)
			{
				throw e;
			}
		}

		/// <summary>
		/// Determines whether the collection contains the specified element.
		/// </summary>
		/// <param name="c">The collection to check.</param>
		/// <param name="obj">The object to locate in the collection.</param>
		/// <returns>true if the element is in the collection.</returns>
		public static bool Contains(System.Collections.ICollection c, System.Object obj)
		{
			bool contains = false;

			//Reflection. Invoke "contains" method for proprietary classes
			System.Reflection.MethodInfo method;
			try
			{
				method = c.GetType().GetMethod("Contains");

				if (method == null)
					method = c.GetType().GetMethod("contains");

				contains = (bool)method.Invoke(c, new System.Object[] {obj});
			}
			catch (System.Exception e)
			{
				throw e;
			}

			return contains;
		}

		/// <summary>
		/// Determines whether the collection contains all the elements in the specified collection.
		/// </summary>
		/// <param name="target">The collection to check.</param>
		/// <param name="c">Collection whose elements would be checked for containment.</param>
		/// <returns>true id the target collection contains all the elements of the specified collection.</returns>
		public static bool ContainsAll(System.Collections.ICollection target, System.Collections.ICollection c)
		{						
			System.Collections.IEnumerator e =  c.GetEnumerator();

			bool contains = false;

			//Reflection. Invoke "containsAll" method for proprietary classes or "Contains" method for each element in the collection
			System.Reflection.MethodInfo method;
			try
			{
				method = target.GetType().GetMethod("containsAll");

				if (method != null)
					contains = (bool)method.Invoke(target, new Object[] {c});
				else
				{					
					method = target.GetType().GetMethod("Contains");
					while (e.MoveNext() == true)
					{
						if ((contains = (bool)method.Invoke(target, new Object[] {e.Current})) == false)
							break;
					}
				}
			}
			catch (System.Exception ex)
			{
				throw ex;
			}

			return contains;
		}

		/// <summary>
		/// Removes the specified element from the collection.
		/// </summary>
		/// <param name="c">The collection where the element will be removed.</param>
		/// <param name="obj">The element to remove from the collection.</param>
		public static bool Remove(System.Collections.ICollection c, System.Object obj)
		{
			bool changed = false;

			//Reflection. Invoke "remove" method for proprietary classes or "Remove" method
			System.Reflection.MethodInfo method;
			try
			{
				method = c.GetType().GetMethod("remove");

				if (method != null)
					method.Invoke(c, new System.Object[] {obj});
				else
				{
					method = c.GetType().GetMethod("Contains");
					changed = (bool)method.Invoke(c, new System.Object[] {obj});
					method = c.GetType().GetMethod("Remove");
					method.Invoke(c, new System.Object[] {obj});
				}
			}
			catch (System.Exception e)
			{
				throw e;
			}

			return changed;
		}

		/// <summary>
		/// Removes all the elements from the specified collection that are contained in the target collection.
		/// </summary>
		/// <param name="target">Collection where the elements will be removed.</param>
		/// <param name="c">Elements to remove from the target collection.</param>
		/// <returns>true</returns>
		public static bool RemoveAll(System.Collections.ICollection target, System.Collections.ICollection c)
		{
			System.Collections.ArrayList al = ToArrayList(c);
			System.Collections.IEnumerator e = al.GetEnumerator();

			//Reflection. Invoke "removeAll" method for proprietary classes or "Remove" for each element in the collection
			System.Reflection.MethodInfo method;
			try
			{
				method = target.GetType().GetMethod("removeAll");

				if (method != null)
					method.Invoke(target, new System.Object[] {al});
				else
				{
					method = target.GetType().GetMethod("Remove");
					System.Reflection.MethodInfo methodContains = target.GetType().GetMethod("Contains");

					while (e.MoveNext() == true)
					{
						while ((bool) methodContains.Invoke(target, new System.Object[] {e.Current}) == true)
							method.Invoke(target, new System.Object[] {e.Current});
					}
				}
			}
			catch (System.Exception ex)
			{
				throw ex;
			}
			return true;
		}

		/// <summary>
		/// Retains the elements in the target collection that are contained in the specified collection
		/// </summary>
		/// <param name="target">Collection where the elements will be removed.</param>
		/// <param name="c">Elements to be retained in the target collection.</param>
		/// <returns>true</returns>
		public static bool RetainAll(System.Collections.ICollection target, System.Collections.ICollection c)
		{
			System.Collections.IEnumerator e = new System.Collections.ArrayList(target).GetEnumerator();
			System.Collections.ArrayList al = new System.Collections.ArrayList(c);

			//Reflection. Invoke "retainAll" method for proprietary classes or "Remove" for each element in the collection
			System.Reflection.MethodInfo method;
			try
			{
				method = c.GetType().GetMethod("retainAll");

				if (method != null)
					method.Invoke(target, new System.Object[] {c});
				else
				{
					method = c.GetType().GetMethod("Remove");

					while (e.MoveNext() == true)
					{
						if (al.Contains(e.Current) == false)
							method.Invoke(target, new System.Object[] {e.Current});
					}
				}
			}
			catch (System.Exception ex)
			{
				throw ex;
			}

			return true;
		}

		/// <summary>
		/// Returns an array containing all the elements of the collection.
		/// </summary>
		/// <returns>The array containing all the elements of the collection.</returns>
		public static System.Object[] ToArray(System.Collections.ICollection c)
		{	
			int index = 0;
			System.Object[] objects = new System.Object[c.Count];
			System.Collections.IEnumerator e = c.GetEnumerator();

			while (e.MoveNext())
				objects[index++] = e.Current;

			return objects;
		}

		/// <summary>
		/// Obtains an array containing all the elements of the collection.
		/// </summary>
		/// <param name="objects">The array into which the elements of the collection will be stored.</param>
		/// <returns>The array containing all the elements of the collection.</returns>
		public static System.Object[] ToArray(System.Collections.ICollection c, System.Object[] objects)
		{	
			int index = 0;

			System.Type type = objects.GetType().GetElementType();
			System.Object[] objs = (System.Object[]) Array.CreateInstance(type, c.Count );

			System.Collections.IEnumerator e = c.GetEnumerator();

			while (e.MoveNext())
				objs[index++] = e.Current;

			//If objects is smaller than c then do not return the new array in the parameter
			if (objects.Length >= c.Count)
				objs.CopyTo(objects, 0);

			return objs;
		}

		/// <summary>
		/// Converts an ICollection instance to an ArrayList instance.
		/// </summary>
		/// <param name="c">The ICollection instance to be converted.</param>
		/// <returns>An ArrayList instance in which its elements are the elements of the ICollection instance.</returns>
		public static System.Collections.ArrayList ToArrayList(System.Collections.ICollection c)
		{
			System.Collections.ArrayList tempArrayList = new System.Collections.ArrayList();
			System.Collections.IEnumerator tempEnumerator = c.GetEnumerator();
			while (tempEnumerator.MoveNext())
				tempArrayList.Add(tempEnumerator.Current);
			return tempArrayList;
		}
	}


	/*******************************/
	/// <summary>
	/// Class to implement a HTTP filter.
	/// </summary>
	public class ServletFilter
	{
		/// <summary>
		/// The HttpRequest to be processed.
		/// </summary>
		public  System.Web.HttpRequest Request;

		/// <summary>
		/// The HttpResponse to be processed.
		/// </summary>
		public  System.Web.HttpResponse Response;

		/// <summary>
		/// An item of the HTTP filter chain.
		/// </summary>
		public  ServletFilterChain ChainItem;

		/// <summary>
		/// The Application object of the project.
		/// </summary>
		public System.Web.HttpApplicationState Application;
	
		/// <summary>
		/// Method to call to start the filtering process.
		/// </summary>
		internal void Run()
		{
			SupportClass.InvokeMethodAsVirtual(this,"doFilter",new System.Object[]{this.Request, this.Response, this.ChainItem});
		}

		/// <summary>
		/// Initializes the HTTP filter.
		/// </summary>
		public  virtual void init()
		{
		}

		/// <summary>
		/// Destroys the http filter.
		/// </summary>
		public  virtual void destroy()
		{
		}

		/// <summary>
		/// Method to call the filtering process.
		/// </summary>
		/// <param name="request">The HttpRequest to be processed.</param>
		/// <param name="response">The HttpResponse to be processed.</param>
		/// <param name="chain">A chain of http filters.</param>
		public virtual void doFilter(System.Web.HttpRequest request, System.Web.HttpResponse response, ServletFilterChain chain)
		{
		}
	}
	/// <summary>
	/// Method to store attributes in a temporal hashtable, to support this feature
	/// in converted servlet filters.
	/// </summary>
	/// <param name="application">The main object application, to store the hashtable.</param>
	/// <param name="request">The current request, to use it's hash code to uniquely identify the hashtable.</param>
	/// <param name="key">The key of the key value pair to be stored.</param>
	/// <param name="val">The value of the key value pair to be stored.</param>
	public static void SetAttribute(System.Web.HttpApplicationState application, System.Web.HttpRequest request, System.Object key, System.Object val)
	{
		System.String id = "FILTERATTR" + request.GetHashCode().ToString();
		
		// Initialize the hashtable for first time it is used.
		if (application[id] == null)
		{
			application[id] = new System.Collections.Hashtable();
		}
		
		System.Collections.Hashtable tempHashTable = (System.Collections.Hashtable)application[id];
		tempHashTable[key] = val;

	}
	/// <summary>
	/// Method to retrieve attributes from a temporal hashtable, to support this feature
	/// in converted servlet filters.
	/// </summary>
	/// <param name="application">The main object application, where the hashtable is stored.</param>
	/// <param name="request">The current request, to use it's hash code to uniquely identify the hashtable.</param>
	/// <param name="key">The key of the key value pair to be retrieved.</param>
	/// <returns>The value of the stored  key value pair.</returns>
	public static System.Object GetAttribute(System.Web.HttpApplicationState application, System.Web.HttpRequest request, System.Object key)
	{
		System.String id = "FILTERATTR" + request.GetHashCode().ToString();
		if (application[id] != null)
		{
			System.Collections.Hashtable hashtable = (System.Collections.Hashtable) application[id] ;
			if (hashtable[key]!= null)
				return hashtable[key];
			else
				return null;
		}
		return null;
	}
	
	/// <summary>
	/// Method to retrieve attributes names from a temporal hashtable 
	/// in converted servlet filters.
	/// </summary>
	/// <param name="application">The main object application, where the hashtable is stored.</param>
	/// <param name="request">The current request, to use it's hash code to uniquely identify the hashtable.</param>
	/// <returns>An enumetator object with attribute names.</returns>
	public static System.Collections.IEnumerator GetAttributeNames (System.Web.HttpApplicationState application, System.Web.HttpRequest request)
	{
		System.String id = "FILTERATTR" + request.GetHashCode().ToString();
		System.Collections.Hashtable hashtable = new System.Collections.Hashtable();
		if (application[id] != null)
		{
			hashtable = (System.Collections.Hashtable)application[id];
		}
		System.Collections.IEnumerator tempEnumerator = hashtable.Keys.GetEnumerator();
		return tempEnumerator;
	}
	/*******************************/
	/// <summary>
	/// Interface used for constructing a HTTP filter chain.
	/// </summary>
	public interface ServletFilterChain
	{
		/// <summary>
		/// Calls the filtering process.
		/// </summary>
		/// <param name="request">The HttpRequest to be processed.</param>
		/// <param name="response">The HttpResponse to be processed.</param>
		void doFilter(System.Web.HttpRequest request, System.Web.HttpResponse response);
	}
	/// <summary>
	/// Class used to represent a Null filter.
	/// </summary>
	internal sealed class NullFilterInstance : ServletFilterChain
	{
		/// <summary>
		/// Stores a main thread.
		/// </summary>
		private System.Threading.Thread main;

		/// <summary>
		/// The HttpRequest to be processed.
		/// </summary>
		public System.Web.HttpRequest CurrRequest = null;

		/// <summary>
		/// The HttpResponse to be processed.
		/// </summary>
		public System.Web.HttpResponse CurrResponse = null;

		/// <summary>
		/// Constructor which receives a thread parameter.
		/// </summary>
		/// <param name="aThread">The thread parameter.</param>
		internal NullFilterInstance(System.Threading.Thread aThread)
		{
			this.main = aThread;
		}

		/// <summary>
		/// Method used to call the filtering process.
		/// </summary>
		/// <param name="request">The HttpRequest to be processed.</param>
		/// <param name="response">The HttpResponse to be processed.</param>
		public void doFilter(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			this.main.Resume();
			System.Threading.Thread.CurrentThread.Suspend();
			request = this.CurrRequest;
			response = this.CurrResponse;
		}
	}
	internal sealed class NextFilterInstance: ServletFilterChain
	{

		/// <summary>
		/// Next filter to be applied.
		/// </summary>
		private ServletFilter                      NextFilter;
	              
		/// <summary>
		/// The HttpRequest to be processed.
		/// </summary>
		public  System.Web.HttpRequest    CurrRequest =null;

		/// <summary>
		/// The HttpResponse to be processed.
		/// </summary>
 		public  System.Web.HttpResponse  CurrResponse = null;

		/// <summary>
		/// Activates next filter in the filter chain.
		/// </summary>
		internal NextFilterInstance (ServletFilter aFilter)
		{
			NextFilter = aFilter;
		}

		/// <summary>
		/// Method used to call the filtering process.
		/// </summary>
		/// <param name="request">The HttpRequest to be processed.</param>
		/// <param name="response">The HttpResponse to be processed.</param>
		public void doFilter(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			NextFilter.doFilter (request, response, NextFilter.ChainItem );
		}
	}

	/*******************************/
	/// <summary>
	/// Class to represent a list of filters.
	/// </summary>
	public sealed class ServletFilterList
	{
		/// <summary>
		/// Collection of requests.
		/// </summary>
		private static System.Collections.Queue Requests =  System.Collections.Queue.Synchronized(new System.Collections.Queue());

		/// <summary>
		/// Array of Filters.
		/// </summary>
		private static ServletFilter[] Filters = {};

		/// <summary>
		/// Flag to detect if the filter list is initialized.
		/// </summary>
		private static bool Initialized = false;

		/// <summary>
		/// Method to suspend a filter.
		/// </summary>
		private static void SuspendMe()
		{
			System.Threading.Thread.CurrentThread.Suspend();
		}

		/// <summary>
		/// Adds a filter to the filter list.
		/// </summary>
		/// <param name="theFilter">The filter to be added to the filter list.</param>
		public static void Add(ServletFilter theFilter)
		{
			lock (typeof(ServletFilterList))
			{
				ServletFilter[] temp = new ServletFilter[Filters.Length + 1];
				Filters.CopyTo(temp, 0);
				temp[Filters.Length] = theFilter;
				Filters = temp;
				if (Filters.Length > 1)
				{
					Filters[Filters.Length - 2].ChainItem = new NextFilterInstance(Filters[Filters.Length - 1]);
				}
			}
		}
			
		/// <summary>
		/// Initializes the filter list.
		/// </summary>
		public static void Init()
		{
			lock (typeof(ServletFilterList))
			{
				for(int i = 0; i < Filters.Length; i++)
				{
					Filters[i].init();
				}
				Initialized = true;
			}
		}

		/// <summary>
		/// Starts the request process.
		/// </summary>
		/// <param name="request">The HttpRequest to be processed.</param>
		/// <param name="response">The HttpResponse to be processed.</param>
		public static void BeginRequest(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			lock (typeof(ServletFilterList))
			{
				if (!Initialized) Init();
			}
			if (Filters.Length > 0)
			{
				lock(Filters)
				{
					Filters[Filters.Length - 1].ChainItem  = new NullFilterInstance(System.Threading.Thread.CurrentThread);
					Filters[0].Request = request;
					Filters[0].Response = response;
					System.Threading.Thread FilterExecution = new System.Threading.Thread(new System.Threading.ThreadStart(Filters[0].Run));
					FilterExecution.Start ();
					SuspendMe();
					lock(Requests.SyncRoot)
					{
						Requests.Enqueue(FilterExecution);
					}
				}
			}
		}

		/// <summary>
		/// Method to be called when the HTTP request ends.
		/// </summary>
		/// <param name="request">The HttpRequest to be processed.</param>
		/// <param name="response">The HttpResponse to be processed.</param>
		public static void EndRequest(System.Web.HttpRequest request, System.Web.HttpResponse response)
		{
			System.Threading.Thread FilterExecution = null;
			lock(Requests.SyncRoot)
			{
				if (Requests.Count > 0)
					FilterExecution = (System.Threading.Thread)Requests.Dequeue();
			}
			if (FilterExecution != null && Filters.Length> 0)
			{
				lock(Filters)
				{
					Filters[Filters.Length - 1].Request = request;
					Filters[Filters.Length - 1].Response = response;
					((NullFilterInstance)Filters[Filters.Length - 1].ChainItem).CurrRequest = request;
					((NullFilterInstance)Filters[Filters.Length - 1].ChainItem).CurrResponse = response;
					FilterExecution.Resume();
					FilterExecution.Join();
				}
			}
		}

		/// <summary>
		/// Method to be called to destroy the filter list.
		/// </summary>
		public static void Destroy()
		{
			lock(typeof(ServletFilterList))
			{
				for (int i = 0; i < Filters.Length; i++)
				{
					Filters[i].destroy();
				}
			}
		}
	}


	/*******************************/
	/// <summary>
	/// Method used to obtain the underlying type of an object to make the correct method call.
	/// </summary>
	/// <param name="tempObject">Object instance received.</param>
	/// <param name="method">Method name to invoke.</param>
	/// <param name="parameters">Object array containing the method parameters.</param>
	/// <returns>The return value of the method called with the proper parameters.</returns>
	public static System.Object InvokeMethodAsVirtual(System.Object tempObject, System.String method, System.Object[] parameters)
	{
		System.Reflection.MethodInfo methodInfo;
		System.Type type = tempObject.GetType();
		if (parameters != null)
		{
			System.Type[] types = new System.Type[parameters.Length];
			for (int index = 0; index < parameters.Length; index++)
				types[index] = parameters[index].GetType();
			methodInfo = type.GetMethod(method, types);
		}
		else methodInfo = type.GetMethod(method);
		try
		{
			return methodInfo.Invoke(tempObject, parameters);
		}
		catch (System.Exception exception)
		{
			throw exception.InnerException;
		}
	}

	/*******************************/
	/// <summary>
	/// Obatins the cookies inside the 'HttpRequest'.
	/// </summary>
	/// <param name="request">The 'HttpRequest' instance used to obtain the 'Cookies' property.</param>
	/// <returns>The 'Cookies' of the giving 'HttpRequest' in a 'HttpCookie' array.</returns>
	public static System.Web.HttpCookie[] GetCookies(System.Web.HttpRequest request)
	{
		System.Web.HttpCookieCollection returnCookies = new System.Web.HttpCookieCollection();
    
		int totalCookies = 0;
		bool isIn = false;

		System.Web.HttpCookie includeCookie = request.Cookies[0];
		System.Web.HttpCookie tempCookie = request.Cookies[0];
    
		for(int indexIncludeCookie = 0; indexIncludeCookie < request.Cookies.Count; indexIncludeCookie++)
		{
			includeCookie = request.Cookies[indexIncludeCookie];

			for (int indexTempCookie = 0; indexTempCookie < request.Cookies.Count; indexTempCookie++)
			{     
				tempCookie = request.Cookies[indexTempCookie];
				if(includeCookie.Name.Equals(tempCookie.Name))
				{
					if (tempCookie.Expires.CompareTo(includeCookie.Expires) < 0 ) 
						includeCookie = tempCookie;                           
				}
			}
			for (int indexAux = 0; indexAux < returnCookies.Count; indexAux ++)
			{
				if(returnCookies.Get(indexAux).Name.Equals(includeCookie.Name))
				{
					isIn = true;
				}
			}
			if(!includeCookie.Secure && !isIn)
			{
				returnCookies.Add(includeCookie);
				totalCookies++;
			}

			isIn = false;     
		}
    
		System.Web.HttpCookie[] arrayReturnCookies = new System.Web.HttpCookie[totalCookies];
		returnCookies.CopyTo(arrayReturnCookies,0);

		return arrayReturnCookies;          
	}


	/*******************************/
	/// <summary>
	/// Constructs a URL from a Http Request
	/// </summary>
	/// <param name="request">Request instance</param>
	/// <returns>A string builder instance with the complete URL</returns>
	public static System.Text.StringBuilder GetRequestURL(System.Web.HttpRequest request)
	{
		System.Uri requestUrl = request.Url;			
		System.Text.StringBuilder returnUrl = new System.Text.StringBuilder();
		returnUrl.Append(requestUrl.Scheme + "://");
		returnUrl.Append(requestUrl.Host);
		if( (requestUrl.Scheme.Equals("http") && (requestUrl.Port != 80)) ||
			(requestUrl.Scheme.Equals("https") && (requestUrl.Port != 443)) )
		{
			returnUrl.Append(':' + requestUrl.Port);
		}			
		returnUrl.Append(requestUrl.AbsolutePath);			
		return returnUrl;
	}

	/*******************************/
	public static string GetRealPath(string s, string vroot)
	{
		if( (s != null) && (s[0] == '/') )
			return "/" + vroot + s;
		else
			return s;
	}
	/*******************************/
	/// <summary>
	/// Gets the HttpRequest and retrieves the header that match with the name passed
	/// </summary>
	/// <param name="request">The HttpRequest instance used to obtain the headers</param>
	/// <param name="name">The name of the headers that match the criteria</param>
	/// <returns>An ienumerator with the headers</returns>
	public static System.Collections.IEnumerator GetHeaders(System.Web.HttpRequest request, System.String name)
	{
		System.Collections.Specialized.NameValueCollection headers = request.Headers;
		Tokenizer tokens = new Tokenizer(headers[name],",");
		System.Collections.ArrayList returnCollection = new System.Collections.ArrayList();
		while(tokens.HasMoreTokens())
		{
			returnCollection.Add(tokens.NextToken());
		}
		return returnCollection.GetEnumerator();
	}

	/*******************************/
	/// <summary>
	/// The class performs token processing in strings
	/// </summary>
	public class Tokenizer: System.Collections.IEnumerator
	{
		/// Position over the string
		private long currentPos = 0;

		/// Include demiliters in the results.
		private bool includeDelims = false;

		/// Char representation of the String to tokenize.
		private char[] chars = null;
			
		//The tokenizer uses the default delimiter set: the space character, the tab character, the newline character, and the carriage-return character and the form-feed character
		private string delimiters = " \t\n\r\f";		

		/// <summary>
		/// Initializes a new class instance with a specified string to process
		/// </summary>
		/// <param name="source">String to tokenize</param>
		public Tokenizer(System.String source)
		{			
			this.chars = source.ToCharArray();
		}

		/// <summary>
		/// Initializes a new class instance with a specified string to process
		/// and the specified token delimiters to use
		/// </summary>
		/// <param name="source">String to tokenize</param>
		/// <param name="delimiters">String containing the delimiters</param>
		public Tokenizer(System.String source, System.String delimiters):this(source)
		{			
			this.delimiters = delimiters;
		}


		/// <summary>
		/// Initializes a new class instance with a specified string to process, the specified token 
		/// delimiters to use, and whether the delimiters must be included in the results.
		/// </summary>
		/// <param name="source">String to tokenize</param>
		/// <param name="delimiters">String containing the delimiters</param>
		/// <param name="includeDelims">Determines if delimiters are included in the results.</param>
		public Tokenizer(System.String source, System.String delimiters, bool includeDelims):this(source,delimiters)
		{
			this.includeDelims = includeDelims;
		}	


		/// <summary>
		/// Returns the next token from the token list
		/// </summary>
		/// <returns>The string value of the token</returns>
		public System.String NextToken()
		{				
			return NextToken(this.delimiters);
		}

		/// <summary>
		/// Returns the next token from the source string, using the provided
		/// token delimiters
		/// </summary>
		/// <param name="delimiters">String containing the delimiters to use</param>
		/// <returns>The string value of the token</returns>
		public System.String NextToken(System.String delimiters)
		{
			//According to documentation, the usage of the received delimiters should be temporary (only for this call).
			//However, it seems it is not true, so the following line is necessary.
			this.delimiters = delimiters;

			//at the end 
			if (this.currentPos == this.chars.Length)
				throw new System.ArgumentOutOfRangeException();
			//if over a delimiter and delimiters must be returned
			else if (   (System.Array.IndexOf(delimiters.ToCharArray(),chars[this.currentPos]) != -1)
				     && this.includeDelims )                	
				return "" + this.chars[this.currentPos++];
			//need to get the token wo delimiters.
			else
				return nextToken(delimiters.ToCharArray());
		}

		//Returns the nextToken wo delimiters
		private System.String nextToken(char[] delimiters)
		{
			string token="";
			long pos = this.currentPos;

			//skip possible delimiters
			while (System.Array.IndexOf(delimiters,this.chars[currentPos]) != -1)
				//The last one is a delimiter (i.e there is no more tokens)
				if (++this.currentPos == this.chars.Length)
				{
					this.currentPos = pos;
					throw new System.ArgumentOutOfRangeException();
				}
			
			//getting the token
			while (System.Array.IndexOf(delimiters,this.chars[this.currentPos]) == -1)
			{
				token+=this.chars[this.currentPos];
				//the last one is not a delimiter
				if (++this.currentPos == this.chars.Length)
					break;
			}
			return token;
		}

				
		/// <summary>
		/// Determines if there are more tokens to return from the source string
		/// </summary>
		/// <returns>True or false, depending if there are more tokens</returns>
		public bool HasMoreTokens()
		{
			//keeping the current pos
			long pos = this.currentPos;
			
			try
			{
				this.NextToken();
			}
			catch (System.ArgumentOutOfRangeException)
			{				
				return false;
			}
			finally
			{
				this.currentPos = pos;
			}
			return true;
		}

		/// <summary>
		/// Remaining tokens count
		/// </summary>
		public int Count
		{
			get
			{
				//keeping the current pos
				long pos = this.currentPos;
				int i = 0;
			
				try
				{
					while (true)
					{
						this.NextToken();
						i++;
					}
				}
				catch (System.ArgumentOutOfRangeException)
				{				
					this.currentPos = pos;
					return i;
				}
			}
		}

		/// <summary>
		///  Performs the same action as NextToken.
		/// </summary>
		public System.Object Current
		{
			get
			{
				return (Object) this.NextToken();
			}		
		}		
		
		/// <summary>
		//  Performs the same action as HasMoreTokens.
		/// </summary>
		/// <returns>True or false, depending if there are more tokens</returns>
		public bool MoveNext()
		{
			return this.HasMoreTokens();
		}
		
		/// <summary>
		/// Does nothing.
		/// </summary>
		public void  Reset()
		{
			;
		}			
	}
	/*******************************/
	/// <summary>
	/// Writes the exception stack trace to the received stream
	/// </summary>
	/// <param name="throwable">Exception to obtain information from</param>
	/// <param name="stream">Output sream used to write to</param>
	public static void WriteStackTrace(System.Exception throwable, System.IO.TextWriter stream)
	{
		stream.Write(throwable.StackTrace);
		stream.Flush();
	}

	/*******************************/
	/// <summary>
	/// Support class used to handle threads
	/// </summary>
	public class ThreadClass : IThreadRunnable
	{
		/// <summary>
		/// The instance of System.Threading.Thread
		/// </summary>
		private System.Threading.Thread threadField;
	      
		/// <summary>
		/// Initializes a new instance of the ThreadClass class
		/// </summary>
		public ThreadClass()
		{
			threadField = new System.Threading.Thread(new System.Threading.ThreadStart(Run));
		}
	 
		/// <summary>
		/// Initializes a new instance of the Thread class.
		/// </summary>
		/// <param name="Name">The name of the thread</param>
		public ThreadClass(System.String Name)
		{
			threadField = new System.Threading.Thread(new System.Threading.ThreadStart(Run));
			this.Name = Name;
		}
	      
		/// <summary>
		/// Initializes a new instance of the Thread class.
		/// </summary>
		/// <param name="Start">A ThreadStart delegate that references the methods to be invoked when this thread begins executing</param>
		public ThreadClass(System.Threading.ThreadStart Start)
		{
			threadField = new System.Threading.Thread(Start);
		}
	 
		/// <summary>
		/// Initializes a new instance of the Thread class.
		/// </summary>
		/// <param name="Start">A ThreadStart delegate that references the methods to be invoked when this thread begins executing</param>
		/// <param name="Name">The name of the thread</param>
		public ThreadClass(System.Threading.ThreadStart Start, System.String Name)
		{
			threadField = new System.Threading.Thread(Start);
			this.Name = Name;
		}
	      
		/// <summary>
		/// This method has no functionality unless the method is overridden
		/// </summary>
		public virtual void Run()
		{
		}
	      
		/// <summary>
		/// Causes the operating system to change the state of the current thread instance to ThreadState.Running
		/// </summary>
		public virtual void Start()
		{
			threadField.Start();
		}
	      
		/// <summary>
		/// Interrupts a thread that is in the WaitSleepJoin thread state
		/// </summary>
		public virtual void Interrupt()
		{
			threadField.Interrupt();
		}
	      
		/// <summary>
		/// Gets the current thread instance
		/// </summary>
		public System.Threading.Thread Instance
		{
			get
			{
				return threadField;
			}
			set
			{
				threadField = value;
			}
		}
	      
		/// <summary>
		/// Gets or sets the name of the thread
		/// </summary>
		public System.String Name
		{
			get
			{
				return threadField.Name;
			}
			set
			{
				if (threadField.Name == null)
					threadField.Name = value; 
			}
		}
	      
		/// <summary>
		/// Gets or sets a value indicating the scheduling priority of a thread
		/// </summary>
		public System.Threading.ThreadPriority Priority
		{
			get
			{
				return threadField.Priority;
			}
			set
			{
				threadField.Priority = value;
			}
		}
	      
		/// <summary>
		/// Gets a value indicating the execution status of the current thread
		/// </summary>
		public bool IsAlive
		{
			get
			{
				return threadField.IsAlive;
			}
		}
	      
		/// <summary>
		/// Gets or sets a value indicating whether or not a thread is a background thread.
		/// </summary>
		public bool IsBackground
		{
			get
			{
				return threadField.IsBackground;
			} 
			set
			{
				threadField.IsBackground = value;
			}
		}
	      
		/// <summary>
		/// Blocks the calling thread until a thread terminates
		/// </summary>
		public void Join()
		{
			threadField.Join();
		}
	      
		/// <summary>
		/// Blocks the calling thread until a thread terminates or the specified time elapses
		/// </summary>
		/// <param name="MiliSeconds">Time of wait in milliseconds</param>
		public void Join(long MiliSeconds)
		{
			lock(this)
			{
				threadField.Join(new System.TimeSpan(MiliSeconds * 10000));
			}
		}
	      
		/// <summary>
		/// Blocks the calling thread until a thread terminates or the specified time elapses
		/// </summary>
		/// <param name="MiliSeconds">Time of wait in milliseconds</param>
		/// <param name="NanoSeconds">Time of wait in nanoseconds</param>
		public void Join(long MiliSeconds, int NanoSeconds)
		{
			lock(this)
			{
				threadField.Join(new System.TimeSpan(MiliSeconds * 10000 + NanoSeconds * 100));
			}
		}
	      
		/// <summary>
		/// Resumes a thread that has been suspended
		/// </summary>
		public void Resume()
		{
			threadField.Resume();
		}
	      
		/// <summary>
		/// Raises a ThreadAbortException in the thread on which it is invoked, 
		/// to begin the process of terminating the thread. Calling this method 
		/// usually terminates the thread
		/// </summary>
		public void Abort()
		{
			threadField.Abort();
		}
	      
		/// <summary>
		/// Raises a ThreadAbortException in the thread on which it is invoked, 
		/// to begin the process of terminating the thread while also providing
		/// exception information about the thread termination. 
		/// Calling this method usually terminates the thread.
		/// </summary>
		/// <param name="stateInfo">An object that contains application-specific information, such as state, which can be used by the thread being aborted</param>
		public void Abort(System.Object stateInfo)
		{
			lock(this)
			{
				threadField.Abort(stateInfo);
			}
		}
	      
		/// <summary>
		/// Suspends the thread, if the thread is already suspended it has no effect
		/// </summary>
		public void Suspend()
		{
			threadField.Suspend();
		}
	      
		/// <summary>
		/// Obtain a String that represents the current Object
		/// </summary>
		/// <returns>A String that represents the current Object</returns>
		public override System.String ToString()
		{
			return "Thread[" + Name + "," + Priority.ToString() + "," + "" + "]";
		}
	     
		/// <summary>
		/// Gets the currently running thread
		/// </summary>
		/// <returns>The currently running thread</returns>
		public static ThreadClass Current()
		{
			ThreadClass CurrentThread = new ThreadClass();
			CurrentThread.Instance = System.Threading.Thread.CurrentThread;
			return CurrentThread;
		}
	}


	/*******************************/
	/// <summary>
	/// This class manages array operations.
	/// </summary>
	public class ArraySupport
	{
		/// <summary>
		/// Compares the entire members of one array whith the other one.
		/// </summary>
		/// <param name="array1">The array to be compared.</param>
		/// <param name="array2">The array to be compared with.</param>
		/// <returns>True if both arrays are equals otherwise it returns false.</returns>
		/// <remarks>Two arrays are equal if they contains the same elements in the same order.</remarks>
		public static bool Equals(System.Array array1, System.Array array2)
		{
			bool result = false;
			if ((array1 == null) && (array2 == null))
				result = true;
			else if ((array1 != null) && (array2 != null))
			{
				if (array1.Length == array2.Length)
				{
					int length = array1.Length;
					result = true;
					for (int index = 0; index < length; index++)
					{
						if (!(array1.GetValue(index).Equals(array2.GetValue(index))))
						{
							result = false;
							break;
						}
					}
				}
			}
			return result;
		}

		/// <summary>
		/// Fills the array with an specific value from an specific index to an specific index.
		/// </summary>
		/// <param name="array">The array to be filled.</param>
		/// <param name="fromindex">The first index to be filled.</param>
		/// <param name="toindex">The last index to be filled.</param>
		/// <param name="val">The value to fill the array with.</param>
		public static void Fill(System.Array array, System.Int32 fromindex, System.Int32 toindex, System.Object val)
		{
			System.Object Temp_Object = val;
			System.Type elementtype = array.GetType().GetElementType();
			if (elementtype != val.GetType())
				Temp_Object = System.Convert.ChangeType(val, elementtype);
			if (array.Length == 0)
				throw (new System.NullReferenceException());
			if (fromindex > toindex)
				throw (new System.ArgumentException());
			if ((fromindex < 0) || ((System.Array)array).Length < toindex)
				throw (new System.IndexOutOfRangeException());
			for (int index = (fromindex > 0) ? fromindex-- : fromindex; index < toindex; index++)
				array.SetValue(Temp_Object, index);
		}

		/// <summary>
		/// Fills the array with an specific value.
		/// </summary>
		/// <param name="array">The array to be filled.</param>
		/// <param name="val">The value to fill the array with.</param>
		public static void Fill(System.Array array, System.Object val)
		{
			Fill(array, 0, array.Length, val);
		}
	}


	/*******************************/
	/// <summary>Reads a number of characters from the current source Stream and writes the data to the target array at the specified index.</summary>
	/// <param name="sourceStream">The source Stream to read from.</param>
	/// <param name="target">Contains the array of characteres read from the source Stream.</param>
	/// <param name="start">The starting index of the target array.</param>
	/// <param name="count">The maximum number of characters to read from the source Stream.</param>
	/// <returns>The number of characters read. The number will be less than or equal to count depending on the data available in the source Stream. Returns -1 if the end of the stream is reached.</returns>
	public static System.Int32 ReadInput(System.IO.Stream sourceStream, sbyte[] target, int start, int count)
	{
		// Returns 0 bytes if not enough space in target
		if (target.Length == 0)
			return 0;

		byte[] receiver = new byte[target.Length];
		int bytesRead   = sourceStream.Read(receiver, start, count);

		// Returns -1 if EOF
		if (bytesRead == 0)	
			return -1;
                
		for(int i = start; i < start + bytesRead; i++)
			target[i] = (sbyte)receiver[i];
                
		return bytesRead;
	}

	/// <summary>Reads a number of characters from the current source TextReader and writes the data to the target array at the specified index.</summary>
	/// <param name="sourceTextReader">The source TextReader to read from</param>
	/// <param name="target">Contains the array of characteres read from the source TextReader.</param>
	/// <param name="start">The starting index of the target array.</param>
	/// <param name="count">The maximum number of characters to read from the source TextReader.</param>
	/// <returns>The number of characters read. The number will be less than or equal to count depending on the data available in the source TextReader. Returns -1 if the end of the stream is reached.</returns>
	public static System.Int32 ReadInput(System.IO.TextReader sourceTextReader, sbyte[] target, int start, int count)
	{
		// Returns 0 bytes if not enough space in target
		if (target.Length == 0) return 0;

		char[] charArray = new char[target.Length];
		int bytesRead = sourceTextReader.Read(charArray, start, count);

		// Returns -1 if EOF
		if (bytesRead == 0) return -1;

		for(int index=start; index<start+bytesRead; index++)
			target[index] = (sbyte)charArray[index];

		return bytesRead;
	}

	/*******************************/
	/// <summary>
	/// Checks if the giving File instance is a directory or file, and returns his Length
	/// </summary>
	/// <param name="file">The File instance to check</param>
	/// <returns>The length of the file</returns>
	public static long FileLength(System.IO.FileInfo file)
	{
		if (file.Exists)
			return file.Length;
		else 
			return 0;
	}

	/*******************************/
/// <summary>
/// Provides support for DateFormat
/// </summary>
public class DateTimeFormatManager
{
	static public DateTimeFormatHashTable manager = new DateTimeFormatHashTable();

	/// <summary>
	/// Hashtable class to provide functionality for dateformat properties
	/// </summary>
	public class DateTimeFormatHashTable :System.Collections.Hashtable 
	{
		/// <summary>
		/// Sets the format for datetime.
		/// </summary>
		/// <param name="format">DateTimeFormat instance to set the pattern</param>
		/// <param name="newPattern">A string with the pattern format</param>
		public void SetDateFormatPattern(System.Globalization.DateTimeFormatInfo format, System.String newPattern)
		{
			if (this[format] != null)
				((DateTimeFormatProperties) this[format]).DateFormatPattern = newPattern;
			else
			{
				DateTimeFormatProperties tempProps = new DateTimeFormatProperties();
				tempProps.DateFormatPattern  = newPattern;
				Add(format, tempProps);
			}
		}

		/// <summary>
		/// Gets the current format pattern of the DateTimeFormat instance
		/// </summary>
		/// <param name="format">The DateTimeFormat instance which the value will be obtained</param>
		/// <returns>The string representing the current datetimeformat pattern</returns>
		public System.String GetDateFormatPattern(System.Globalization.DateTimeFormatInfo format)
		{
			if (this[format] == null)
				return "d-MMM-yy";
			else
				return ((DateTimeFormatProperties) this[format]).DateFormatPattern;
		}
		
		/// <summary>
		/// Sets the datetimeformat pattern to the giving format
		/// </summary>
		/// <param name="format">The datetimeformat instance to set</param>
		/// <param name="newPattern">The new datetimeformat pattern</param>
		public void SetTimeFormatPattern(System.Globalization.DateTimeFormatInfo format, System.String newPattern)
		{
			if (this[format] != null)
				((DateTimeFormatProperties) this[format]).TimeFormatPattern = newPattern;
			else
			{
				DateTimeFormatProperties tempProps = new DateTimeFormatProperties();
				tempProps.TimeFormatPattern  = newPattern;
				Add(format, tempProps);
			}
		}

		/// <summary>
		/// Gets the current format pattern of the DateTimeFormat instance
		/// </summary>
		/// <param name="format">The DateTimeFormat instance which the value will be obtained</param>
		/// <returns>The string representing the current datetimeformat pattern</returns>
		public System.String GetTimeFormatPattern(System.Globalization.DateTimeFormatInfo format)
		{
			if (this[format] == null)
				return "h:mm:ss tt";
			else
				return ((DateTimeFormatProperties) this[format]).TimeFormatPattern;
		}

		/// <summary>
		/// Internal class to provides the DateFormat and TimeFormat pattern properties on .NET
		/// </summary>
		class DateTimeFormatProperties
		{
			public System.String DateFormatPattern = "d-MMM-yy";
			public System.String TimeFormatPattern = "h:mm:ss tt";
		}
	}	
}
	/*******************************/
	/// <summary>
	/// Gets the DateTimeFormat instance using the culture passed as parameter and sets the pattern to the time or date depending of the value
	/// </summary>
	/// <param name="dateStyle">The desired date style.</param>
	/// <param name="timeStyle">The desired time style</param>
	/// <param name="culture">The CultureInfo instance used to obtain the DateTimeFormat</param>
	/// <returns>The DateTimeFomatInfo of the culture and with the desired date or time style</returns>
	public static System.Globalization.DateTimeFormatInfo GetDateTimeFormatInstance(int dateStyle, int timeStyle, System.Globalization.CultureInfo culture)
	{
		const int NULLPATERN = -1;
		const int PATERN_1 = 0;
		const int PATERN_2 = 1;
		const int PATERN_3 = 2;
		const int PATERN_4 = 3;
		System.Globalization.DateTimeFormatInfo format = culture.DateTimeFormat;
		 
		switch (timeStyle)
		{
			case NULLPATERN:
				DateTimeFormatManager.manager.SetTimeFormatPattern(format, "");
				break;

			case PATERN_1:
				DateTimeFormatManager.manager.SetTimeFormatPattern(format, format.LongTimePattern);
				break;

			case PATERN_2:
				DateTimeFormatManager.manager.SetTimeFormatPattern(format, "h:mm:ss tt zzz");
				break;

			case PATERN_3:
				DateTimeFormatManager.manager.SetTimeFormatPattern(format, "h:mm:ss tt");
				break;

			case PATERN_4:
				DateTimeFormatManager.manager.SetTimeFormatPattern(format, format.ShortTimePattern);
				break;
		}

		switch (dateStyle)
		{
			case NULLPATERN:
				DateTimeFormatManager.manager.SetDateFormatPattern(format, "");
				break;

			case PATERN_1:
				DateTimeFormatManager.manager.SetDateFormatPattern(format, format.LongDatePattern);
				break;

			case PATERN_2:
				DateTimeFormatManager.manager.SetDateFormatPattern(format, "MMMM d, yyy" );
				break;

			case PATERN_3:
				DateTimeFormatManager.manager.SetDateFormatPattern(format, "MMM d, yyy"  );
				break;

			case PATERN_4:
				DateTimeFormatManager.manager.SetDateFormatPattern(format, format.ShortDatePattern);
				break;
		}

		return format;
	}

	/*******************************/
	/// <summary>
	/// This method returns the literal value received
	/// </summary>
	/// <param name="literal">The literal to return</param>
	/// <returns>The received value</returns>
	public static long Identity(long literal)
	{
		return literal;
	}

	/// <summary>
	/// This method returns the literal value received
	/// </summary>
	/// <param name="literal">The literal to return</param>
	/// <returns>The received value</returns>
	public static ulong Identity(ulong literal)
	{
		return literal;
	}

	/// <summary>
	/// This method returns the literal value received
	/// </summary>
	/// <param name="literal">The literal to return</param>
	/// <returns>The received value</returns>
	public static float Identity(float literal)
	{
		return literal;
	}

	/// <summary>
	/// This method returns the literal value received
	/// </summary>
	/// <param name="literal">The literal to return</param>
	/// <returns>The received value</returns>
	public static double Identity(double literal)
	{
		return literal;
	}

	/*******************************/
	/// <summary>
	/// Provides support for ByteArrayInputStream
	/// </summary>
	public class ByteArrayInputManager
	{
		static public ByteArrayInputHashTable manager = new ByteArrayInputHashTable();

		/// <summary>
		/// A hastable to store and keep the track position
		/// </summary>
		public class ByteArrayInputHashTable: System.Collections.Hashtable 
		{
			/// <summary>
			/// Reset the point of read to the marked position
			/// </summary>
			/// <param name="stream">The instance of InputStream</param>
			/// <returns>The current mark position</returns>
			public long ResetMark(System.IO.Stream stream)
			{
				if (this[stream] != null)
					return ((MarkProperties)this[stream]).markposition;
				else
					return stream.Position;
			}

			/// <summary>
			/// Marks a position into the stream
			/// </summary>
			/// <param name="index">The position that will be marked</param>
			/// <param name="stream">The stream to mark</param>
			public void MarkPosition(int index, System.IO.Stream stream)
			{
				if (this[stream] == null)
				{
					MarkProperties tempProps = new MarkProperties();
					tempProps.markposition= stream.Position;
					Add(stream, tempProps);
				}
				else
				{
					((MarkProperties)this[stream]).markposition = stream.Position;
				}
			}

			/// <summary>
			/// Returns the previously marked position of the stream or zero.
			/// </summary>
			/// <param name="stream">The stream from which the marked position is returned</param>
			/// <returns>The marked position of the specified stream or zero in case it isn't marked yet</returns>
			public int ReturnMarkPosition(System.IO.Stream stream)
			{
				if (this[stream] != null)
				{
					return (int)((MarkProperties)this[stream]).markposition;
				}
				else
				{
					return 0;
				}
			}

			/// <summary>
			/// Inner class. Used to have the properties of mark on .NET
			/// </summary>
			class MarkProperties
			{
				public long markposition = 0;
			}
		}
	}
}
