Passive_recon

In passive reconnaissance, you rely on publicly available knowledge. It is the knowledge that you can access from publicly available resources without directly engaging with the target.

We will learn three command-line tools:

`whois` to query WHOIS servers

`nslookup` to query DNS servers

`dig` to query DNS servers

We use `whois` to query WHOIS records, while we use `nslookup` and `dig` to query DNS database records. These are all publicly available records and hence do not alert the target.

Also, there are two other online services:

DNSDumpster

Shodan.io

Let's begin with `whois`

WHOIS is a request and response protocol that follows the [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt) specification. A WHOIS server listens on TCP port 43 for incoming requests.

The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing. 

The WHOIS server replies with various information related to the domain requested. Of particular interest, we can learn:

Registrar: Via which registrar was the domain name registered?

Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)

Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?

Name Server: Which server to ask to resolve the domain name?

To get this information, we need to use a `whois` client or an online service. Many online services provide `whois` information;

However, it is generally faster and more convenient to use your local `whois` client. Using your local Linux machine, such as Parrot or Kali, you can easily access your `whois` client on the terminal.

The syntax is `whois DOMAIN_NAME`, where `DOMAIN_NAME` is the domain about which you are trying to get more information. Consider the following example executing `whois example.com`.

![Screenshot From 2025-07-18 21-07-43](https://github.com/user-attachments/assets/ae0e6811-9493-476f-a4bb-fe03b73d3017)

We can see plenty of information; we will inspect them in the order displayed. First, we notice that we were redirected to `whois.namecheap.com` to get our information. 

In this case and at the time being, `namecheap.com` is maintaining the WHOIS record for this domain name. Furthermore, we can see the creation date along with the last-update date and expiration date.

Next, we obtain information about the registrar and the registrant. We can find the registrant’s name and contact information unless they are using some privacy service. 

Although not displayed above, we get the admin and tech contacts for this domain. Finally, we see the domain name servers that we should query if we have any DNS records to look up.

The information collected can be inspected to find new attack surfaces, such as social engineering or technical attacks. 

For instance, depending on the scope of the penetration test, you might consider an attack against the email server of the admin user or the DNS servers, assuming they are owned by your client and fall within the scope of the penetration test.

It is important to note that due to automated tools abusing WHOIS queries to harvest email addresses, many WHOIS services take measures against this. 

They might redact email addresses, for instance. Moreover, many registrants subscribe to privacy services to avoid their email addresses being harvested by spammers and keep their information private.

Let's move on to `nslookup` and `dig`

Let's IP address of a domain name using `nslookup`, which stands for Name Server Look Up. You need to issue the command `nslookup DOMAIN_NAME`, for example, `nslookup example.com`. Or, more generally,

you can use `nslookup OPTIONS DOMAIN_NAME SERVER`. These three main parameters are:

`OPTIONS` contains the query type as shown in the table below. For instance, you can use `A` for IPv4 addresses and `AAAA` for IPv6 addresses.
`
DOMAIN_NAME` is the domain name you are looking up.

`SERVER` is the DNS server that you want to query. You can choose any local or public DNS server to query. Cloudflare offers `1.1.1.1` and `1.0.0.1`, Google offers `8.8.8.8` and `8.8.4.4`, and Quad9 offers `9.9.9.9` and `149.112.112.112`.

There are many more public DNS servers that you can choose from if you want alternatives to your ISP’s DNS servers.

Query type	Result
`A`	       IPv4 Addresses
`AAAA`	     IPv6 Addresses
`CNAME`	     Canonical Name
`MX`	       Mail Servers
`SOA`	       Start of Authority
`TXT`	      TXT Records

For instance, `nslookup -type=A example.com 1.1.1.1` (or `nslookup -type=a example.com 1.1.1.1` as it is case-insensitive) can be used to return all the IPv4 addresses used by `example.com`.

For `dig` we use `dig example.com A` to discover ipv4 address.


















