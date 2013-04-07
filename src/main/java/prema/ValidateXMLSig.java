package prema;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

/**
 * This is a simple example of validating an XML Signature using the JSR 105 API. It assumes the key needed to validate
 * the signature is contained in a KeyValue KeyInfo.
 */
public class ValidateXMLSig
{
	//
	// Synopsis: java ValidateXMLSig [document]
	//
	//	  where "document" is the name of a file containing the XML document
	//	  to be validated.
	//
	public static void main(String[] args) throws Exception
	{
		if (args.length < 1)
		{
			System.out.println("Usage: java ValidateXMLSig <fileName>");
			return;
		}

		// Instantiate the document to be validated
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf
				.newDocumentBuilder()
				.parse(new FileInputStream(args[0]));

		// Find Signature element
		NodeList nl = doc.getElementsByTagNameNS(
				XMLSignature.XMLNS,
				"Signature"
		);

		if (nl.getLength() == 0)
		{
			throw new Exception("Cannot find Signature element");
		}

		// Create a DOM XMLSignatureFactory that will be used to unmarshal the
		// document containing the XMLSignature
		String providerName = System.getProperty(
				"jsr105Provider",
				"org.jcp.xml.dsig.internal.dom.XMLDSigRI"
		);

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance(
				"DOM",
				(Provider) Class
						.forName(providerName)
						.newInstance()
		);

		for (int i = 0; i < nl.getLength(); i++)
		{
			// Create a DOMValidateContext and specify a KeyValue KeySelector
			// and document context
			DOMValidateContext valContext = new DOMValidateContext(
					new KeyValueKeySelector(),
					nl.item(i)
			);

			// unmarshal the XMLSignature
			XMLSignature signature = fac.unmarshalXMLSignature(valContext);

			// Validate the XMLSignature (generated above)
			boolean coreValidity = signature.validate(valContext);

			// Check core validation status
			if (coreValidity == false)
			{
				System.out.println(
						String.format("Signature %s failed core validation", i)
				);

				boolean sv = signature.getSignatureValue().validate(valContext);
				System.out.println(
						String.format("Signature %s validation status: %s", i, sv)
				);

				// check the validation status of each Reference
				Iterator it = signature
						.getSignedInfo()
						.getReferences()
						.iterator();

				for (int j = 0; it.hasNext(); j++)
				{
					Reference reference = (Reference) it.next();
					boolean refValid = reference
							.validate(valContext);
					System.out.println(
							String.format(
									"Signature %s ref['%s'] validity status: %s",
									i, j, reference
							)
					);
				}
			}
			else
			{
				System.out.println(
						String.format("Signature %s passed core validation", i)
				);
			}
		}
	}

	/**
	 * KeySelector which retrieves the public key out of the KeyValue element and returns it. NOTE: If the key algorithm
	 * doesn't match signature algorithm, then the public key will be ignored.
	 */
	private static class KeyValueKeySelector extends KeySelector
	{
		public KeySelectorResult select(KeyInfo keyInfo,
		                                KeySelector.Purpose purpose,
		                                AlgorithmMethod method,
		                                XMLCryptoContext context)
				throws KeySelectorException
		{
			if (keyInfo == null)
			{
				throw new KeySelectorException("Null KeyInfo object!");
			}
			SignatureMethod sm = (SignatureMethod) method;
			List list = keyInfo.getContent();

			for (int i = 0; i < list.size(); i++)
			{
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof KeyValue)
				{
					PublicKey pk = null;
					try
					{
						pk = ((KeyValue) xmlStructure).getPublicKey();
					}
					catch (KeyException ke)
					{
						throw new KeySelectorException(ke);
					}

					// make sure algorithm is compatible with method
					if (algEquals(sm.getAlgorithm(), pk.getAlgorithm()))
					{
						return new SimpleKeySelectorResult(pk);
					}
				}

				if (xmlStructure instanceof X509Data)
				{
					List x509datalist = ((X509Data) xmlStructure).getContent();
					for (int y = 0; y < x509datalist.size(); y++)
					{
						PublicKey pk = null;
						if (x509datalist.get(y) instanceof X509Certificate)
						{
							pk = ((X509Certificate) x509datalist.get(y)).getPublicKey();
							// make sure algorithm is compatible with method
							if (algEquals(sm.getAlgorithm(), pk.getAlgorithm()))
							{
								return new SimpleKeySelectorResult(pk);
							}
						}
					}
				}
			}
			throw new KeySelectorException("No KeyValue element found!");
		}

		static boolean algEquals(String algURI, String algName)
		{
			if (algName.equalsIgnoreCase("DSA") &&
			    algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1))
			{
				return true;
			}
			else if (algName.equalsIgnoreCase("RSA") &&
			         algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	private static class SimpleKeySelectorResult implements KeySelectorResult
	{
		private PublicKey pk;

		SimpleKeySelectorResult(PublicKey pk)
		{
			this.pk = pk;
		}

		public Key getKey() { return pk; }
	}


}