/// <summary> </summary>
using System;
using IAccessController = org.owasp.esapi.interfaces.IAccessController;
using IAuthenticator = org.owasp.esapi.interfaces.IAuthenticator;
using IEncoder = org.owasp.esapi.interfaces.IEncoder;
using IEncryptor = org.owasp.esapi.interfaces.IEncryptor;
using IExecutor = org.owasp.esapi.interfaces.IExecutor;
using IHTTPUtilities = org.owasp.esapi.interfaces.IHTTPUtilities;
using IIntrusionDetector = org.owasp.esapi.interfaces.IIntrusionDetector;
using IRandomizer = org.owasp.esapi.interfaces.IRandomizer;
using ISecurityConfiguration = org.owasp.esapi.interfaces.ISecurityConfiguration;
using IValidator = org.owasp.esapi.interfaces.IValidator;
namespace org.owasp.esapi
{
	
	/// <author>  rdawes
	/// 
	/// </author>
	public class ESAPI
	{
		/// <param name="accessController">the accessController to set
		/// </param>
		public static IAccessController AccessController
		{
			set
			{
				ESAPI.accessController_Renamed_Field = value;
			}
			
		}
		/// <param name="authenticator">the authenticator to set
		/// </param>
		public static IAuthenticator Authenticator
		{
			set
			{
				ESAPI.authenticator_Renamed_Field = value;
			}
			
		}
		/// <param name="encoder">the encoder to set
		/// </param>
		public static IEncoder Encoder
		{
			set
			{
				ESAPI.encoder_Renamed_Field = value;
			}
			
		}
		/// <param name="encryptor">the encryptor to set
		/// </param>
		public static IEncryptor Encryptor
		{
			set
			{
				ESAPI.encryptor_Renamed_Field = value;
			}
			
		}
		/// <param name="executor">the executor to set
		/// </param>
		public static IExecutor Executor
		{
			set
			{
				ESAPI.executor_Renamed_Field = value;
			}
			
		}
		/// <param name="httpUtilities">the httpUtilities to set
		/// </param>
		public static IHTTPUtilities HttpUtilities
		{
			set
			{
				ESAPI.httpUtilities_Renamed_Field = value;
			}
			
		}
		/// <param name="intrusionDetector">the intrusionDetector to set
		/// </param>
		public static IIntrusionDetector IntrusionDetector
		{
			set
			{
				ESAPI.intrusionDetector_Renamed_Field = value;
			}
			
		}
		/// <param name="randomizer">the randomizer to set
		/// </param>
		public static IRandomizer Randomizer
		{
			set
			{
				ESAPI.randomizer_Renamed_Field = value;
			}
			
		}
		/// <param name="securityConfiguration">the securityConfiguration to set
		/// </param>
		public static ISecurityConfiguration SecurityConfiguration
		{
			set
			{
				ESAPI.securityConfiguration_Renamed_Field = value;
			}
			
		}
		/// <param name="validator">the validator to set
		/// </param>
		public static IValidator Validator
		{
			set
			{
				ESAPI.validator_Renamed_Field = value;
			}
			
		}
		
		private static IAccessController accessController_Renamed_Field = null;
		
		private static IAuthenticator authenticator_Renamed_Field = null;
		
		private static IEncoder encoder_Renamed_Field = null;
		
		private static IEncryptor encryptor_Renamed_Field = null;
		
		private static IExecutor executor_Renamed_Field = null;
		
		private static IHTTPUtilities httpUtilities_Renamed_Field = null;
		
		private static IIntrusionDetector intrusionDetector_Renamed_Field = null;
		
		//    private static ILogger logger = null;
		
		private static IRandomizer randomizer_Renamed_Field = null;
		
		private static ISecurityConfiguration securityConfiguration_Renamed_Field = null;
		
		private static IValidator validator_Renamed_Field = null;
		
		/// <summary> prevent instantiation of this class</summary>
		private ESAPI()
		{
		}
		
		/// <returns> the accessController
		/// </returns>
		public static IAccessController accessController()
		{
			if (ESAPI.accessController_Renamed_Field == null)
				ESAPI.accessController_Renamed_Field = new AccessController();
			return ESAPI.accessController_Renamed_Field;
		}
		
		/// <returns> the authenticator
		/// </returns>
		public static IAuthenticator authenticator()
		{
			if (ESAPI.authenticator_Renamed_Field == null)
				ESAPI.authenticator_Renamed_Field = new Authenticator();
			return ESAPI.authenticator_Renamed_Field;
		}
		
		/// <returns> the encoder
		/// </returns>
		public static IEncoder encoder()
		{
			if (ESAPI.encoder_Renamed_Field == null)
				ESAPI.encoder_Renamed_Field = new Encoder();
			return ESAPI.encoder_Renamed_Field;
		}
		
		/// <returns> the encryptor
		/// </returns>
		public static IEncryptor encryptor()
		{
			if (ESAPI.encryptor_Renamed_Field == null)
				ESAPI.encryptor_Renamed_Field = new Encryptor();
			return ESAPI.encryptor_Renamed_Field;
		}
		
		/// <returns> the executor
		/// </returns>
		public static IExecutor executor()
		{
			if (ESAPI.executor_Renamed_Field == null)
				ESAPI.executor_Renamed_Field = new Executor();
			return ESAPI.executor_Renamed_Field;
		}
		
		/// <returns> the httpUtilities
		/// </returns>
		public static IHTTPUtilities httpUtilities()
		{
			if (ESAPI.httpUtilities_Renamed_Field == null)
				ESAPI.httpUtilities_Renamed_Field = new HTTPUtilities();
			return ESAPI.httpUtilities_Renamed_Field;
		}
		
		/// <returns> the intrusionDetector
		/// </returns>
		public static IIntrusionDetector intrusionDetector()
		{
			if (ESAPI.intrusionDetector_Renamed_Field == null)
				ESAPI.intrusionDetector_Renamed_Field = new IntrusionDetector();
			return ESAPI.intrusionDetector_Renamed_Field;
		}
		
		//    /**
		//     * @return the logger
		//     */
		//    public static  ILogger getLogger() {
		//        if (ESAPI.logger == null)
		//            return Logger();
		//        return ESAPI.logger;
		//    }
		//
		//    /**
		//     * @param logger the logger to set
		//     */
		//    public static  void setLogger(ILogger logger) {
		//        ESAPI.logger = logger;
		//    }
		//
		/// <returns> the randomizer
		/// </returns>
		public static IRandomizer randomizer()
		{
			if (ESAPI.randomizer_Renamed_Field == null)
				ESAPI.randomizer_Renamed_Field = new Randomizer();
			return ESAPI.randomizer_Renamed_Field;
		}
		
		/// <returns> the securityConfiguration
		/// </returns>
		public static ISecurityConfiguration securityConfiguration()
		{
			if (ESAPI.securityConfiguration_Renamed_Field == null)
				ESAPI.securityConfiguration_Renamed_Field = new SecurityConfiguration();
			return ESAPI.securityConfiguration_Renamed_Field;
		}
		
		/// <returns> the validator
		/// </returns>
		public static IValidator validator()
		{
			if (ESAPI.validator_Renamed_Field == null)
				ESAPI.validator_Renamed_Field = new Validator();
			return ESAPI.validator_Renamed_Field;
		}
	}
}