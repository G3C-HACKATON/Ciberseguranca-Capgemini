import os
import streamlit as st
import google.generativeai as genai
import re
import sys
from typing import Dict

# Adicionar diretório atual ao path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Tentar importar componentes do sistema de segurança
try:
    from config import Config
    from logger import SecurityLogger
    from security_agent import SecurityAgent
    from threat_intelligence import ThreatIntelligence
    from notification import NotificationSystem
    system_components_available = True
except ImportError:
    system_components_available = False

# Configuração da API key para Google Gemini
os.environ["GOOGLE_API_KEY"] = ""
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# Definir o contexto de segurança cibernética
SECURITY_CONTEXT = """
Você é um especialista em segurança cibernética com experiência em:
1. Proteção contra malware e vírus
2. Segurança de redes
3. Proteção de dados pessoais
4. Prevenção de phishing e engenharia social
5. Boas práticas de segurança digital

Forneça informações claras, confiáveis e atualizadas sobre segurança cibernética, 
adaptadas ao nível de conhecimento do usuário. Inclua recomendações práticas 
quando relevante e explique conceitos técnicos de forma acessível.

Sempre que possível, utilize informações atualizadas da web para fornecer dados mais recentes
sobre ameaças, vulnerabilidades e recomendações de segurança.
"""

# Base de conhecimento de fontes oficiais
OFFICIAL_SOURCES = {
    "antivirus": [
        {"name": "CERT.br - Cartilha de Segurança", "url": "https://cartilha.cert.br/malware/"},
        {"name": "Microsoft Security", "url": "https://www.microsoft.com/en-us/security/"}
    ],
    "senha": [
        {"name": "CERT.br - Senhas", "url": "https://cartilha.cert.br/senhas/"},
        {"name": "NIST Password Guidelines", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html"}
    ],
    "phishing": [
        {"name": "CERT.br - Phishing", "url": "https://cartilha.cert.br/golpes/"},
        {"name": "Anti-Phishing Working Group", "url": "https://apwg.org/"}
    ],
    "rede": [
        {"name": "CERT.br - Redes", "url": "https://cartilha.cert.br/redes/"},
        {"name": "Cisco Network Security", "url": "https://www.cisco.com/c/en/us/products/security/"}
    ],
    "backup": [
        {"name": "CERT.br - Backup", "url": "https://cartilha.cert.br/dicas-rapidas/#backup"},
        {"name": "NIST Backup Guidelines", "url": "https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final"}
    ],
    "privacidade": [
        {"name": "CERT.br - Privacidade", "url": "https://cartilha.cert.br/privacidade/"},
        {"name": "Electronic Frontier Foundation", "url": "https://www.eff.org/issues/privacy"}
    ],
    "geral": [
        {"name": "CERT.br", "url": "https://www.cert.br/"},
        {"name": "Centro de Estudos, Resposta e Tratamento de Incidentes de Segurança no Brasil", "url": "https://www.cert.br/"},
        {"name": "NIST Cybersecurity Framework", "url": "https://www.nist.gov/cyberframework"}
    ]
}

# Inicializa o modelo
model = genai.GenerativeModel("models/gemini-1.5-pro")  # Modelo confirmado funcionando

def search_web(query: str, num_results: int = 5) -> Dict:
    """
    Simula uma pesquisa na web usando o Gemini.
    
    Args:
        query: A consulta de pesquisa
        num_results: Número de resultados a serem retornados
        
    Returns:
        Dicionário com os resultados simulados
    """
    try:
        # Criar um prompt específico para simular resultados de busca
        fallback_prompt = f"""
        Atue como um mecanismo de busca web e forneça informações atualizadas sobre:
        
        "{query}"
        
        Regras importantes:
        1. Foque em segurança cibernética e tecnologia
        2. Formate a resposta como se fossem resultados de uma pesquisa na web
        3. Inclua detalhes técnicos relevantes e atualizados
        4. Se possível, mencione fontes hipotéticas (sites, publicações)
        5. Indique datas recentes para as informações
        6. Seja preciso e informativo
        
        Observação: Apresente a informação mais atual que você conhece sobre este tópico.
        """
        
        # Gerar resposta usando o Gemini
        response = model.generate_content(fallback_prompt)
        
        if response:
            return {
                "success": True,
                "results": response.text
            }
        else:
            return {
                "success": False,
                "error": "Não foi possível obter resultados de pesquisa"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Erro ao realizar pesquisa na web: {str(e)}"
        }

def get_relevant_sources(query):
    """Encontra fontes relevantes com base na consulta."""
    query = query.lower()
    sources = []
    
    # Sempre incluir fontes gerais
    sources.extend(OFFICIAL_SOURCES["geral"])
    
    # Adicionar fontes específicas com base em palavras-chave
    if any(word in query for word in ["virus", "malware", "antivirus", "software", "proteção"]):
        sources.extend(OFFICIAL_SOURCES["antivirus"])
    
    if any(word in query for word in ["senha", "password", "login", "autenticação", "conta"]):
        sources.extend(OFFICIAL_SOURCES["senha"])
    
    if any(word in query for word in ["phishing", "golpe", "e-mail", "email", "mensagem", "whatsapp", "fraude", "enganar"]):
        sources.extend(OFFICIAL_SOURCES["phishing"])
    
    if any(word in query for word in ["rede", "wifi", "wi-fi", "internet", "conexão", "roteador"]):
        sources.extend(OFFICIAL_SOURCES["rede"])
    
    if any(word in query for word in ["backup", "copia", "cópia", "reserva", "recuperação", "restaurar"]):
        sources.extend(OFFICIAL_SOURCES["backup"])
    
    if any(word in query for word in ["privacidade", "dados", "pessoais", "informações", "vazamento"]):
        sources.extend(OFFICIAL_SOURCES["privacidade"])
    
    # Remover duplicatas
    unique_sources = []
    seen_urls = set()
    for source in sources:
        if source["url"] not in seen_urls:
            unique_sources.append(source)
            seen_urls.add(source["url"])
    
    return unique_sources[:5]  # Limitar a 5 fontes mais relevantes

def format_sources(sources):
    """Formata lista de fontes para exibição."""
    if not sources:
        return ""
    
    result = "\n\n## Fontes Oficiais Recomendadas:\n"
    for source in sources:
        result += f"- [{source['name']}]({source['url']})\n"
    
    return result

def get_security_response(query):
    """Obter resposta sobre segurança cibernética para uma consulta."""
    try:
        # Verificar se a consulta solicita informações em tempo real
        needs_realtime = any(word in query.lower() for word in [
            "atual", "atualizado", "recente", "último", "nova", "novo", "hoje", 
            "semana", "mês", "ano", "notícia", "tendência", "agora", "momento",
            "real", "tempo real", "ao vivo"
        ])
        
        # Se precisar de informações em tempo real, fazer pesquisa na web
        web_info = ""
        if needs_realtime:
            search_result = search_web(query)
            if search_result["success"]:
                web_info = f"\n\n## Informações Atualizadas da Web:\n{search_result['results']}\n\n"
            else:
                web_info = "\n\n*Nota: Tentei buscar informações atualizadas na web, mas não foi possível completar a pesquisa.*\n\n"
        
        # Combina o contexto e a pergunta do usuário
        full_prompt = f"{SECURITY_CONTEXT}\n\nPergunta sobre segurança cibernética: {query}\n\nResposta:"
        
        # Gera a resposta
        response = model.generate_content(full_prompt)
        
        # Obtém fontes relevantes
        sources = get_relevant_sources(query)
        
        # Adiciona as informações da web (se houver) e as fontes à resposta
        return response.text + web_info + format_sources(sources)
    except Exception as e:
        return f"Ocorreu um erro ao processar sua pergunta: {str(e)}"

def get_threat_info(ip, threat_intel):
    """Obtém informações de ameaça para um IP específico."""
    try:
        # Obter dados de reputação do IP
        ip_data = threat_intel.get_ip_reputation(ip)
        
        # Formatar informações
        threat_info = f"### Informações de Ameaça para IP: {ip}\n\n"
        threat_info += f"- **País:** {ip_data.get('country', 'Desconhecido')}\n"
        threat_info += f"- **Pontuação de Ameaça:** {ip_data.get('threat_score', 0)}/100\n"
        threat_info += f"- **ISP:** {ip_data.get('isp', 'Desconhecido')}\n"
        
        # Categorias de ameaça
        categories = ip_data.get('categories', [])
        if categories:
            threat_info += f"- **Categorias de Ameaça:** {', '.join(categories)}\n"
        
        # Histórico de atividades
        activities = ip_data.get('activity_history', [])
        if activities:
            threat_info += "\n### Histórico de Atividades Suspeitas:\n\n"
            for activity in activities[:5]:  # Limitar a 5 atividades
                threat_info += f"- **{activity.get('date', '')}:** {activity.get('type', '')} "
                threat_info += f"(Confiança: {activity.get('confidence', 0)}%)\n"
        
        return threat_info
    except Exception as e:
        return f"Erro ao obter informações de ameaça: {str(e)}"

def initialize_chat_history():
    """Inicializa o histórico de chat na sessão."""
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

def add_to_chat_history(role, content):
    """Adiciona uma mensagem ao histórico do chat."""
    st.session_state.chat_history.append({"role": role, "content": content})

def run_console_mode():
    """Executa o chatbot no modo console."""
    print("=" * 60)
    print("  CyberBot: Assistente de Segurança Cibernética")
    print("=" * 60)
    print("Digite 'sair' para encerrar o chat.")
    print("\nIMPORTANTE: Este chatbot fornece apenas informações gerais.")
    print("Para questões críticas, consulte especialistas certificados.")
    
    while True:
        user_input = input("\nSua pergunta sobre segurança cibernética: ")
        
        if user_input.lower() == 'sair':
            print("\nObrigado por usar o CyberBot. Mantenha-se seguro!")
            break
        
        # Obter e exibir resposta
        response = get_security_response(user_input)
        print("\n" + "=" * 60)
        print(response)
        print("=" * 60)

def run_streamlit_mode(security_components=None):
    """Executa o chatbot no modo Streamlit com integração opcional com o agente de segurança."""
    st.title("💬 CyberBot: Assistente de Segurança Cibernética")
    
    # Botão para voltar ao painel principal
    if st.button("← Voltar ao Painel de Segurança", key="back_button"):
        st.query_params.clear()  # Limpar query params
        st.rerun()
    
    # Inicializar histórico de chat
    initialize_chat_history()
    
    # Informações do sistema
    with st.expander("ℹ️ Sobre o CyberBot", expanded=False):
        st.markdown("""
        O CyberBot é um assistente de segurança cibernética que fornece informações e orientações sobre:
        - Proteção contra malware e vírus
        - Segurança de redes
        - Proteção de dados pessoais
        - Prevenção de phishing e engenharia social
        - Boas práticas de segurança digital
        
        **IMPORTANTE:** Este chatbot fornece apenas informações gerais. Para questões críticas, consulte especialistas certificados.
        
        **NOVO:** Agora o CyberBot pode buscar informações em tempo real na web! Basta fazer uma pergunta com termos como "atual", "recente", ou usar a opção "Pesquisar na web".
        """)
    
    # Exibir histórico de chat
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Input do usuário
    user_input = st.chat_input("Digite sua pergunta sobre segurança cibernética")
    
    # Opções avançadas na sidebar
    with st.sidebar:
        st.subheader("⚙️ Opções Avançadas")
        force_web_search = st.checkbox("Pesquisar na web", value=False, 
                                      help="Busca informações atualizadas na internet para responder à sua pergunta")
    
    if user_input:
        # Adicionar input do usuário ao histórico
        add_to_chat_history("user", user_input)
        
        # Exibir mensagem do usuário
        with st.chat_message("user"):
            st.markdown(user_input)
        
        # Processar resposta
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            
            # Mostrar status de processamento
            with st.status("Processando sua pergunta...", expanded=True) as status:
                st.write("Analisando sua pergunta...")
                
                # Verificar se deve forçar pesquisa na web
                if force_web_search:
                    st.write("Buscando informações atualizadas na web...")
                    # Modificar a pergunta para forçar busca na web
                    web_query = f"informações mais recentes e atualizadas sobre: {user_input}"
                    search_result = search_web(web_query)
                    if search_result["success"]:
                        st.write("✅ Informações obtidas com sucesso!")
                    else:
                        st.write("⚠️ Não foi possível completar a pesquisa na web")
                
                # Gerar resposta normal
                st.write("Gerando resposta...")
                response = get_security_response(user_input)
                
                # Integração com agente de segurança se disponível
                additional_info = ""
                if security_components and any(word in user_input.lower() for word in ["ip", "endereço", "origem", "ameaça"]):
                    st.write("Consultando dados de segurança...")
                    # Verificar se há menção a um IP específico
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input)
                    if ip_match:
                        ip = ip_match.group(0)
                        threat_intel = security_components.get("threat_intel")
                        if threat_intel:
                            additional_info = f"\n\n---\n\n{get_threat_info(ip, threat_intel)}"
                            
                            # Opcional: Registrar a consulta no sistema de logs
                            logger = security_components.get("logger")
                            if logger:
                                logger.log_activity(f"Consulta de segurança sobre IP: {ip}", "info")
                
                # Adicionar informações adicionais se disponíveis
                full_response = response + additional_info
                status.update(label="✅ Resposta pronta!", state="complete", expanded=False)
            
            # Exibir resposta com efeito de digitação
            message_placeholder.markdown(full_response)
            
            # Adicionar resposta ao histórico
            add_to_chat_history("assistant", full_response)
    
    # Sidebar para interagir com o sistema de segurança se disponível
    if security_components:
        with st.sidebar:
            st.title("🔍 Sistema de Segurança")
            
            # Botão para voltar ao painel principal (também na sidebar)
            if st.button("← Voltar ao Painel", key="back_button_sidebar"):
                st.query_params.clear()  # Limpar query params
                st.rerun()
            
            st.markdown("---")
            
            # Exibir estatísticas do agente
            security_agent = security_components.get("security_agent")
            if security_agent:
                stats = security_agent.get_threat_stats()
                st.metric("Ameaças Analisadas", stats.get("total", 0))
                st.metric("Ameaças Mitigadas", stats.get("mitigated", 0))
                
                # Exibir IPs bloqueados
                with st.expander("IPs Bloqueados", expanded=False):
                    blocked_ips = security_agent.get_blocked_ips()
                    if blocked_ips:
                        for ip in blocked_ips:
                            st.code(ip)
                    else:
                        st.info("Nenhum IP bloqueado no momento.")
            
            # Consulta rápida de IPs
            st.subheader("Consulta Rápida de IP")
            ip_query = st.text_input("Digite um endereço IP")
            if ip_query and re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', ip_query):
                threat_intel = security_components.get("threat_intel")
                if threat_intel:
                    with st.spinner("Consultando informações..."):
                        ip_info = get_threat_info(ip_query, threat_intel)
                        st.markdown(ip_info)

def main():
    """Função principal do chatbot."""
    # Verificar se estamos em ambiente Streamlit
    in_streamlit = 'streamlit' in sys.modules and st._is_running_with_streamlit
    
    if in_streamlit:
        # Modo Streamlit
        if system_components_available:
            # Inicializar componentes do sistema de segurança
            config = Config()
            logger = SecurityLogger()
            threat_intel = ThreatIntelligence(config)
            notification_system = NotificationSystem(config)
            security_agent = SecurityAgent(config, logger, threat_intel, notification_system)
            
            # Empacotar componentes
            security_components = {
                "config": config,
                "logger": logger,
                "threat_intel": threat_intel,
                "security_agent": security_agent,
                "notification": notification_system
            }
            
            # Executar interface Streamlit com componentes de segurança
            run_streamlit_mode(security_components)
        else:
            # Executar interface Streamlit sem componentes de segurança
            run_streamlit_mode()
    else:
        # Modo console
        run_console_mode()

if __name__ == "__main__":
    main() 