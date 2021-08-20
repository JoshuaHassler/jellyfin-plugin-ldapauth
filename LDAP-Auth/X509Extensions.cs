using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Jellyfin.Plugin.LDAP_Auth
{
    /// <summary>
    /// Gets plugin name.
    /// </summary>
    public static class X509Extensions
    {
        /// <summary>
        /// Gets plugin name.
        /// </summary>
        /// <param name="chain">Username to authenticate.</param>
        /// <returns>A with the authentication result.</returns>
        public static string ToDisplayString(this X509Chain chain)
        {
            var b = new StringBuilder();

            b.AppendLine($"[{nameof(chain.ChainPolicy.RevocationFlag)}]");
            b.AppendLine($"  {chain.ChainPolicy.RevocationFlag}");
            b.AppendLine();
            b.AppendLine($"[{nameof(chain.ChainPolicy.RevocationMode)}]");
            b.AppendLine($"  {chain.ChainPolicy.RevocationMode}");
            b.AppendLine();
            b.AppendLine($"[{nameof(chain.ChainPolicy.VerificationFlags)}]");
            b.AppendLine($"  {chain.ChainPolicy.VerificationFlags}");
            b.AppendLine();
            b.AppendLine($"[{nameof(chain.ChainPolicy.VerificationTime)}]");
            b.AppendLine($"  {chain.ChainPolicy.VerificationTime}");
            b.AppendLine();
            b.AppendLine($"[Application Policy]");
            foreach (var policy in chain.ChainPolicy.ApplicationPolicy)
            {
                b.AppendLine($"  {policy.ToDisplayString()}");
            }

            b.AppendLine();
            b.AppendLine($"[Certificate Policy]");
            foreach (var policy in chain.ChainPolicy.CertificatePolicy)
            {
                b.AppendLine($"  {policy.ToDisplayString()}");
            }

            b.AppendLine();
            b.AppendLine($"[Elements]");
            foreach (var (element, index) in chain.ChainElements.Cast<X509ChainElement>().Select((element, index) => (element, index)))
            {
                b.AppendLine();
                b.AppendLine($"[Element {index + 1}]");
                b.AppendLine();
                b.Append(element.Certificate.ToString());
                b.AppendLine();
                b.AppendLine($"[Status]");
                foreach (var status in element.ChainElementStatus)
                {
                    b.AppendLine($"  {status.ToDisplayString()}");
                }
            }

            return b.ToString();
        }

        /// <summary>
        /// Gets plugin name.
        /// </summary>
        /// <param name="oid">Username to authenticate.</param>
        /// <returns>A with the authentication result.</returns>
        public static string ToDisplayString(this Oid oid)
        {
            return oid.FriendlyName == oid.Value
                ? $"{oid.Value}"
                : $"{oid.FriendlyName}: {oid.Value}";
        }

        /// <summary>
        /// Gets plugin name.
        /// </summary>
        /// <param name="status">Username to authenticate.</param>
        /// <returns>A with the authentication result.</returns>
        public static string ToDisplayString(this X509ChainStatus status)
        {
            return $"{status.Status}: {status.StatusInformation}";
        }
    }
}