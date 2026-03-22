import boto3
import csv
import json
from botocore.exceptions import BotoCoreError, ClientError 


SENSITIVE_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    3389: 'RDP',
    5900: 'VNC',

    3306: 'MySQL',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    1521: 'Oracle DB',
    27017: 'MongoDB',
    6370: 'Redis',
    9200: 'Elasticsearch',

    8080: 'HTTP-alt-intern-app',
    8443: 'HTTPS-alt',
    21: 'FTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
}

#ec2 = boto3.client("ec2", region_name="sa-east-1")

def classify_risk(port,cidr):
    if cidr in ["0.0.0.0/0","::/0"]:
        if port in [22,23,3389,5900]:
            return "Crítico"
        elif port in [3306,5432,1433,1521,27017,6370,9200]:
            return "Alto"
        elif port in [8080,8443,21,25,110,143]:
            return "Médio"
        elif port == -1:
            return "Crítico"
    return "Baixo"

def get_recommendation(port, cidr):
    if cidr in ["0.0.0.0/0","::/0"]:
        if port in [22,23,3389,5900]:
            return "Fechar a porta ou restringir o acesso a IPs confiáveis ou outras alternativas como bastion/VPN/SSM Session Manager."
        elif port in [3306,5432,1433,1521,27017,6370,9200]:
            return "Restringir o acesso aos bancos apenas para aplicações/subnets/sg autorizados"
        elif port in [8080,8443,21,25,110,143]:
            return "Verificar a necessidade de exposição e considerar restrições adicionais."
        elif port == -1:
            return "!!!! EVITE EXPOR TODAS AS PORTAS PARA O MUNDO !!!!"
        return "Nenhuma ação necessária"

def analyze_security_groups():
    ec2 = boto3.client("ec2")
    findings = []

    try:
        response = ec2.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
        print("Total de Security Groups encontrados:", len(security_groups))

    except (BotoCoreError, ClientError) as error:
        print(f"Erro ao consultar Security Groups: {error}")

    for sg in security_groups:
        print("|----------------------------------- ----------------------------|")
        print("Security Group:", sg.get("GroupName"))

        group_id = sg.get("GroupId")
        group_name = sg.get("GroupName")
        vpc_id = sg.get("VpcId", "N/A")

        permissions = sg.get("IpPermissions", [])
        print("Quantidade de regras de entrada:", len(permissions))

        for permission in sg.get("IpPermissions",[]):

            from_port   = permission.get("FromPort", -1)
            to_port     = permission.get("ToPort", -1)
            protocol    = permission.get("IpProtocol", "N/A")

            ipv4_ranges = permission.get("IpRanges", [])
            ipv6_ranges = permission.get("Ipv6Ranges", [])

            for ip_range in ipv4_ranges:
                cidr = ip_range.get("CidrIp")
                #print("IPv4 encontrado:", cidr)
                process_finding(findings, group_id, group_name, vpc_id, protocol, from_port, to_port, cidr)
                        
            for ip_range in ipv6_ranges:
                cidr = ip_range.get("CidrIpv6")
                #print("IPv6 encontrado:", cidr)    
                process_finding(findings, group_id, group_name, vpc_id, protocol, from_port, to_port, cidr)
            
    return findings


def process_finding(findings, group_id, group_name, vpc_id, protocol, from_port, to_port, cidr):
    if cidr not in ["0.0.0.0/0", "::/0"]:
        print("CIDR ignorado")
        return
      
    if from_port == -1 and to_port == -1:
        port_desc = "Todas as portas"
        risk = classify_risk(-1, cidr)
        recommendation = get_recommendation(-1, cidr)

        findings.append({
            "security_group_id": group_id,
            "security_group_name": group_name,
            "vpc_id": vpc_id,
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "cidr": cidr,
            "port_description": port_desc,
            "risk": risk,
            "recommendation": recommendation
        })
        return

    for port in range(from_port, to_port + 1):
        print("Porta exposta:", port)

        if port in [22, 23, 3389, 5900, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 8080, 8443, 21, 25, 110, 143]:
            risk = classify_risk(port, cidr)
            recommendation = get_recommendation(port, cidr)

            findings.append({
                "security_group_id": group_id,
                "security_group_name": group_name,
                "vpc_id": vpc_id,
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "cidr": cidr,
                "port_description": str(port),
                "risk": risk,
                "recommendation": recommendation
            })


def export_csv(findings, filename="output/findings.csv"):
    fieldnames = [
        "security_group_id",
        "security_group_name",
        "vpc_id",
        "protocol",
        "from_port",
        "to_port",
        "cidr",
        "port_description",
        "risk",
        "recommendation"
    ]

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

def export_json(findings, filename="output/findings.json"):
    with open(filename, "w", encoding="utf-8") as jsonfile:
        json.dump(findings, jsonfile, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    results = analyze_security_groups()

    if not results:
        print("Nenhuma exposição crítica encontrada.")
    else:
        print(f"{len(results)} achados encontrados. Exportando resultados...")
        export_csv(results)
        export_json(results)
        print("Exportação concluída.")