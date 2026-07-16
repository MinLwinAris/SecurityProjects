import dns.resolver
import pandas as pd

resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8"]
resolver.timeout = 5
resolver.lifetime = 5

results = []

with open("domains.txt", "r", encoding="utf-8") as f:
    domains = [line.strip() for line in f if line.strip()]

for domain in domains:

    status = ""
    primary_ns = ""
    serial = ""

    try:
        answers = resolver.resolve(domain, "SOA")

        for rdata in answers:
            status = "Published"
            primary_ns = str(rdata.mname)
            serial = str(rdata.serial)

    except dns.resolver.NXDOMAIN:
        status = "NXDOMAIN"

    except dns.resolver.NoAnswer:
        status = "NO_SOA"

    except dns.resolver.NoNameservers:
        status = "SERVFAIL"

    except dns.exception.Timeout:
        status = "TIMEOUT"

    except Exception as e:
        status = str(e)

    results.append({
        "Domain": domain,
        "SOA Status": status,
        "Primary NS": primary_ns,
        "Serial": serial
    })

df = pd.DataFrame(results)

output_file = "SOA_Audit_Result.xlsx"

df.to_excel(output_file, index=False)

print(f"Completed. Result saved to {output_file}")