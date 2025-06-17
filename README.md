Email Automation System
Aplicação GUI para automação de envio de emails com anexos PDF, extração de endereços de email de documentos e monitoramento de pastas.

📌 Visão Geral
Este sistema automatiza o processo de:

Monitoramento de uma pasta em busca de novos arquivos PDF

Extração de endereços de email dos documentos (usando múltiplos métodos)

Envio dos PDFs para os emails encontrados via SendGrid

Organização dos arquivos processados em pastas de "enviados" e "erros"

Geração de logs e estatísticas do processo

✨ Funcionalidades
Interface gráfica moderna com CustomTkinter

Monitoramento em tempo real de pasta (watchdog)

Múltiplos métodos de extração de texto de PDFs:

PyPDF2

pdfplumber

pdfminer

OCR com Tesseract (fallback)

Validação de emails com verificação DNS MX

Envio via SendGrid com tratamento de anexos

Templates personalizáveis para emails normais e de erro

Estatísticas em tempo real do processamento

Sistema de logs completo com opção de salvar

Persistência de configurações entre execuções

⚙️ Requisitos
Python 3.7+

Bibliotecas listadas em requirements.txt

🛠 Instalação
Clone o repositório:

bash
git clone https://github.com/seu-usuario/email-automation.git
cd email-automation
Crie e ative um ambiente virtual (recomendado):

bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
Instale as dependências:

bash
pip install -r requirements.txt
Configure o Tesseract OCR (se necessário):

Descomente e ajuste a linha pytesseract.pytesseract.tesseract_cmd no código

Ou instale o Tesseract no seu sistema e adicione ao PATH

🚀 Como Usar
Execute o aplicativo:

bash
python email_automation.py
Na aba Configuração:

Insira sua API Key do SendGrid

Configure o email remetente

Defina as pastas de monitoramento, enviados e erros

Personalize os templates de email

Na aba Monitoramento:

Clique em "Iniciar Monitoramento" para começar a observar a pasta

Ou use "Processar Pasta" para executar uma única vez

Acompanhe os logs na aba Logs

⚠️ Observações Importantes
O sistema requer uma conta no SendGrid com API Key válida

Para melhor precisão no OCR, instale o Tesseract com suporte a português

Arquivos PDF protegidos por senha podem não ser processados corretamente

O sistema cria automaticamente as pastas de destino se não existirem

📄 Licença
Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes.

Desenvolvido por israel salles de oliveira - [sallesisrael66@gmail.com]
