#!/usr/bin/env python3
"""
vulnerability_scanner.py
protótipo educativo para detecção básica de csrf/xss e indícios de sqli.
uso: main.py http://testphp.vulnweb.com
aviso: usar apenas em alvos autorizados.
"""

# importações
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode  # para manipular urls de forma segura
import requests  # para fazer requisições http
from bs4 import BeautifulSoup  # para parse do html
import sys  # para ler argumentos da linha de comando
import re  # expressões regulares (detecção de padrões)
import logging  # logging simples
from typing import List, Optional  # anotações de tipo (opcional)

# configuração básica de logging (nível info por padrão)
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# cabeçalhos padrão para as requisições (identificação simples do scanner)
default_headers = {
    "user-agent": "vulnscanner/1.0 (+educational; )"
      #contact: email@.com)"
}

# padrão regex para detectar mensagens de erro de banco de dados comuns
# essa regex tenta cobrir mensagens típicas de mysql, oracle, mssql etc.
sql_error_patterns = re.compile(
    r"(sql syntax|mysql|syntax error|unclosed quotation mark|database error|ora-)", re.IGNORECASE
)

# parâmetros comuns que costumam aparecer em urls e onde vale testar payloads
common_params = ['id', 'q', 'search', 'page', 'cat']

# payloads básicos usados apenas para demonstração (não execute em alvos sem autorização)
default_payloads = ["' or '1'='1' -- ", "1' or 1=1 -- ", "1; drop table users --"]

# sessão requests reaproveitada (mantém cookies/headers e reduz overhead)
session = requests.Session()
# atualiza headers da sessão; note: keys em headers ficam normalmente em formato 'User-Agent',
# mas requests trata case-insensitivamente. mantemos tudo em minúsculas por consistência textual.
session.headers.update(default_headers)
session.max_redirects = 5  # limite simples para redirecionamentos

# ------------------------------------------------------------
# funções utilitárias
# ------------------------------------------------------------

def build_url_with_param(base: str, param: str, value: str) -> str:
    """
    constroi uma url a partir de uma base, substituindo/adicinando o parâmetro informado
    - usa urllib.parse para escapar corretamente os valores e não quebrar a querystring
    - retorna a url rebuildada como string
    """
    parsed = urlparse(base)  # parse da url em componentes
    # parse_qsl retorna lista de pares; transformamos em dict para manipular facilmente
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    # definimos (ou sobrescrevemos) o parâmetro que vamos testar
    qs[param] = value
    # reconstroi a query string escapando corretamente
    new_qs = urlencode(qs, doseq=True)
    # substitui a query antiga pela nova e reconstrói a url completa
    rebuilt = urlunparse(parsed._replace(query=new_qs))
    return rebuilt


def check_csrf_protection(form) -> bool:
    """
    verifica indícios simples de token csrf dentro do formulário ou em meta tags:
    - procura por inputs cujo name contenha 'csrf', 'token' ou patterns similares
    - considera inputs hidden com value longo como possível token
    - procura por meta tags como <meta name="csrf-token" content="...">
    retorna True se houver indício de proteção, False caso contrário
   
    """
    # checa inputs do formulário
    for input_tag in form.find_all('input'):
        # pega o nome do input (pode ser None)
        name = input_tag.get('name', '') or ''
        # procura por padrões comuns em nomes de token csrf
        if re.search(r'csrf|token|__requestverificationtoken', name, re.IGNORECASE):
            return True
        # heurística: input hidden com value longo possivelmente é um token
        if input_tag.get('type', '').lower() == 'hidden' and input_tag.get('value'):
            if len(input_tag.get('value')) > 8:
                return True

    # alguns frameworks colocam o token em meta tags no head
    # procuramos no parent imediato (página inteira) por meta tags com 'csrf' no name
    if form.find_parent() is not None:
        soup = form.find_parent()
        meta = soup.find('meta', attrs={'name': re.compile(r'csrf', re.IGNORECASE)})
        if meta and meta.get('content'):
            return True

    # se nada foi encontrado, retorna falso (ou seja, sem indicação de token)
    return False


def test_sql_injection(url: str, param: str, payload: str, timeout: float = 5.0) -> Optional[str]:
    """
    testa um parâmetro de url com um payload de sql injection simples:
    - monta a url com build_url_with_param
    - faz uma requisição get e procura por padrões de erro de banco de dados
    - também verifica se o payload aparece refletido sem escape (heurística para falta de sanitização)
    - retorna uma string com achado ou None caso não detecte nada
    """
    try:
        test_url = build_url_with_param(url, param, payload)
        logging.debug(f"testando url: {test_url}")
        resp = session.get(test_url, timeout=timeout)  # timeout evita travar indefinidamente
        # busca por padrões de erro de sql no corpo da resposta
        if sql_error_patterns.search(resp.text):
            return f"possível sqli: payload '{payload}' no parâmetro '{param}' -> {test_url}"
        # heurística adicional: se o payload aparece refletido no html sem escaping
        if payload.strip() in resp.text:
            return f"possível reflexão do payload '{payload}' em {test_url} (pode indicar falta de sanitização)"
        return None
    except requests.RequestException as e:
        # em caso de erro de rede/logging, apenas registramos em debug e retornamos None
        logging.debug(f"request falhou para {url}: {e}")
        return None


def scan_website(base_url: str, params: List[str] = None, payloads: List[str] = None) -> List[str]:
    """
    função principal que:
    - faz uma requisição inicial para obter o html da página
    - procura por formulários e verifica proteção csrf (heurística)
    - testa parâmetros comuns com payloads simples de sqli
    - retorna uma lista de mensagens/achados
    """
    params = params or common_params
    payloads = payloads or default_payloads
    results = []

    # tentativa de obter a página inicial
    try:
        resp = session.get(base_url, timeout=6.0)
        resp.raise_for_status()  # levanta exceção para códigos 4xx/5xx
    except requests.RequestException as e:
        # se não for possível acessar a url, retornamos o erro como resultado
        return [f"erro ao acessar {base_url}: {e}"]

    # parse do html com beautifulsoup
    soup = BeautifulSoup(resp.text, 'html.parser')
    forms = soup.find_all('form')  # encontra todos os formulários

    # analisa formulários encontrados
    if not forms:
        results.append("nenhum formulário encontrado na página inicial.")
    else:
        for i, form in enumerate(forms, start=1):
            protected = check_csrf_protection(form)
            if protected:
                results.append(f"formulário {i}: token csrf detectado.")
            else:
                results.append(f"formulário {i}: possível falta de proteção csrf / vulnerabilidade xss (heurística).")

    # testes simples de sqli em parâmetros comuns
    for param in params:
        for payload in payloads:
            r = test_sql_injection(base_url, param, payload)
            if r:
                results.append(r)

    # se não houver nenhum achado, avisamos que nenhuma vulnerabilidade foi detectada
    if not results:
        results.append("nenhuma vulnerabilidade detectada (heurística básica).")

    return results


def main():
    """
    entrada do script:
    - espera receber 1 argumento: a url base a ser escaneada
    - normaliza a url adicionando http:// se necessário
    - executa o scan e imprime o relatório
    """
    if len(sys.argv) != 2:
        # instrução de uso simples (em minúsculas conforme pedido)
        print("uso: python vulnerability_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    # se o usuário não passou o schema, adicionamos http:// por padrão
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    logging.info(f"escaneando {url} ... (uso educacional)")
    findings = scan_website(url)

    # imprime relatório simples e legível
    print("\n=== relatório de vulnerabilidades ===")
    for f in findings:
        print("- " + f)


# bloco padrão: executa main quando o script é chamado diretamente
if __name__ == "__main__":
    main()
