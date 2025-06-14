import streamlit as st
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle
import re
from datetime import datetime, timedelta
import base64
import email
import google.auth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import html # 导入 html 模块用于处理 HTML 实体

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_service():
    creds = None
    # The file token.pickle stores the user's access and refresh tokens
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    # If there are no (valid) credentials available, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                st.error("""
                ❌ 错误：找不到 credentials.json 文件！
                
                请按照以下步骤操作：
                1. 访问 https://console.cloud.google.com/
                2. 创建新项目或选择现有项目
                3. 在左侧菜单选择"API 和服务" > "库"
                4. 搜索并启用 "Gmail API"
                5. 在左侧菜单选择"API 和服务" > "凭证"
                6. 点击"创建凭证" > "OAuth 客户端 ID"
                7. 选择应用类型为"桌面应用"
                8. 下载凭证文件并重命名为 'credentials.json'
                9. 将 credentials.json 放在与此程序相同的目录下
                """)
                return None
            try:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            except Exception as e:
                st.error(f"""
                ❌ 错误：无法加载 credentials.json 文件！
                
                错误信息：{str(e)}
                
                请确保：
                1. credentials.json 文件格式正确
                2. 文件内容完整且未损坏
                3. 您已正确启用 Gmail API
                4. 您已正确配置 OAuth 同意屏幕
                """)
                return None
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)

def extract_verification_code(message):
    # 优先匹配特定格式的验证码，这些通常最准确
    patterns_high_priority = [
        r'请填写以下验证码完成邮箱验证[^0-9]*([0-9]{4,8})',
        r'验证码[^0-9]*([0-9]{4,8})[^0-9]*分钟内有效',
        r'验证码[^0-9]*([0-9]{4,8})[^0-9]*有效',
        r'Your code is:?\s*([0-9]{4,8})',
        r'(\d{4,8}) is your verification code',
        r'([0-9]{4,8})\s*是您的验证码',
        r'(\d{4,8})\s*为您的验证码',
        r'OTP:\s*([0-9]{4,8})',
        r'pin:\s*([0-9]{4,8})'
    ]

    # 通用模式，用于匹配被关键词包围的数字
    patterns_general_context = [
        r'(?:验证码|verification|code|OTP|PIN|密码)[：:\s]*([0-9]{4,8})',
        r'([0-9]{4,8})(?:[^\d\n]*?(?:验证码|verification|code|OTP|PIN|密码))',
        r'(?<=您的验证码是)\s*([0-9]{4,8})',
        r'(?<=验证码为)\s*([0-9]{4,8})',
        r'([0-9]{4,8})\s*是您的验证码'
    ]

    # 最后，作为补充，查找独立的4-8位数字，并结合上下文判断
    patterns_isolated = [
        r'(?<![0-9])([0-9]{4,8})(?![0-9])' # 确保是独立的数字序列
    ]

    all_patterns = patterns_high_priority + patterns_general_context + patterns_isolated
    
    for pattern in all_patterns:
        matches = re.finditer(pattern, message, re.IGNORECASE)
        for match in matches:
            code = match.group(1)
            if 4 <= len(code) <= 8: # 验证码长度在4到8位之间
                # 对于通用和独立的模式，需要更严格的上下文检查
                if pattern in patterns_general_context or pattern in patterns_isolated:
                    # 检查数字前后是否有其他数字，以避免提取到长串数字中的一部分
                    code_start = match.start(1)
                    code_end = match.end(1)
                    before_code = message[max(0, code_start - 1):code_start]
                    after_code = message[code_end:min(len(message), code_end + 1)]
                    
                    if before_code.isdigit() or after_code.isdigit():
                        continue # 如果前后有数字，跳过这个匹配，可能不是独立的验证码
                    
                    # 对于独立数字，还需要结合上下文关键词判断
                    if pattern in patterns_isolated:
                        start_context = max(0, match.start() - 50)
                        end_context = min(len(message), match.end() + 50)
                        context = message[start_context:end_context].lower()
                        
                        keywords = ['验证码', 'verification', 'code', 'otp', 'pin', '密码', 'secure', 'authenticate', '确认', '安全']
                        if not any(keyword in context for keyword in keywords):
                            continue # 如果独立数字周围没有相关关键词，跳过
                            
                return code
    return None

def clean_email_body(body):
    """清理邮件内容，移除HTML标签、CSS样式和多余的空行，并将URL转换为超链接"""
    # 解码HTML实体，例如 &copy; 为 ©
    body = html.unescape(body)
    
    # 移除<style>...</style>标签及其内容
    body = re.sub(r'<style[^>]*>.*?<\/style>', '', body, flags=re.DOTALL | re.IGNORECASE)
    
    # 移除<script>...</script>标签及其内容
    body = re.sub(r'<script[^>]*>.*?<\/script>', '', body, flags=re.DOTALL | re.IGNORECASE)
    
    # 移除HTML注释
    body = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL)
    
    # 移除所有HTML标签
    body = re.sub(r'<[^>]+>', '', body)
    
    # Split body into lines for line-by-line processing
    lines = body.split('\n')
    cleaned_lines = []
    
    # Regex to identify lines that look like CSS rules or declarations
    css_pattern = re.compile(r'^[ \t]*(?:[a-zA-Z0-9\\-_\\s,.:#]+\s*\\{[ \t]*|[^\\n]*?:[^\\n]*?;[ \t]*|\\})[ \t]*$', re.IGNORECASE)
    
    for line in lines:
        stripped_line = line.strip()
        # Skip lines that are empty or primarily look like CSS
        if not stripped_line or css_pattern.match(stripped_line):
            continue
        cleaned_lines.append(stripped_line)
            
    # Join lines and then handle multiple newlines
    body = '\n'.join(cleaned_lines)

    # Replace multiple newlines with at most two newlines for better formatting
    body = re.sub(r'\n{3,}', '\n\n', body)

    # Ensure no leading/trailing blank lines from the whole text
    body = body.strip()

    # 移除所有只包含空白字符的行 (再次确保)
    body = '\n'.join(line for line in body.split('\n') if line.strip())

    # 将URL转换为超链接
    url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+(?:/[^\s]*)*')
    body = url_pattern.sub(r'<a href="\g<0>" target="_blank">\g<0></a>', body)

    return body

def get_recent_emails(service, max_results=10):
    try:
        # Get messages from the last 24 hours
        query = 'after:' + (datetime.now() - timedelta(days=1)).strftime('%Y/%m/%d')
        results = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
        messages = results.get('messages', [])

        emails_list = [] # 更名为 emails_list 以避免与循环变量冲突
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            headers = msg['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '无主题')
            date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '无日期')
            
            # Get message body (prioritize plain text)
            body = ''
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                        body = part['body']['data']
                        break
                    elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                        # If no plain text, fall back to HTML and clean it
                        if not body:
                            body = part['body']['data']
            elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
                body = msg['payload']['body']['data']
            
            if body:
                try:
                    body = base64.urlsafe_b64decode(body).decode('utf-8')
                    body = clean_email_body(body)  # 清理邮件内容
                except Exception as e:
                    st.warning(f"解码邮件内容时出错: {e}")
                    body = ''
            
            verification_code = extract_verification_code(body)
            
            emails_list.append({
                'subject': subject,
                'date': date,
                'code': verification_code, # 即使没有识别出验证码，也保留字段
                'body': body  # 添加清理后的邮件内容
            })
        
        return emails_list
    except Exception as e:
        st.error(f"获取邮件时出错: {str(e)}")
        return []

def main():
    st.set_page_config(page_title="Gmail验证码查看器", layout="centered")
    
    # 注入自定义CSS来移除按钮边框和设置图标颜色
    st.markdown("""
    <style>
    /* 确保Streamlit按钮没有边框和阴影 */
    [data-testid="stButton"] button {
        background-color: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0 !important;
        margin: 0 !important;
        width: 40px; /* 增加按钮区域，使其成为圆形并容纳图标 */
        height: 40px; /* 增加按钮区域 */
        border-radius: 50% !important; /* 使按钮成为圆形 */
        display: flex; /* 使用flexbox居中图标 */
        justify-content: center;
        align-items: center;
        outline: none !important;
    }
    [data-testid="stButton"] button:hover {
        border: none !important;
        box-shadow: none !important;
        background-color: rgba(0, 0, 0, 0.05) !important; /* 悬停时稍微有点背景色提示 */
    }
    [data-testid="stButton"] button:focus {
        border: none !important;
        box-shadow: none !important;
        outline: none !important;
        background-color: transparent !important; /* 确保聚焦时背景也透明 */
    }
    [data-testid="stButton"] button:active {
        border: none !important;
        box-shadow: none !important;
        background-color: rgba(0, 0, 0, 0.1) !important; /* 点击时稍微有点背景色 */
    }
    
    /* 特别针对刷新按钮，确保图标是黑色 */
    [data-testid="stButton"] button > div > svg {
        color: black !important;
        font-size: 28px; /* 调整图标大小，使其更显眼 */
    }
    /* 隐藏按钮文字 */
    [data-testid="stButton"] button > div:last-child {
        display: none !important;
    }

    /* 调整数字输入框的标签字体 */
    div[data-testid="stNumberInput"] label p {
        font-weight: normal; /* 保持普通字体，或根据需要调整 */
        margin-bottom: 0.1rem; /* 减少标签与输入框之间的间距 */
        font-size: 0.9rem; /* 稍微调小标签字体，与主标题区分 */
    }
    /* 调整数字输入框的实际输入区域 */
    div[data-testid="stNumberInput"] div[data-testid="stInputContainer"] {
        margin-top: -0.2rem; /* 向上微调输入框位置 */
    }

    /* 移除st.expander的边框和阴影，使其更紧凑 */
    div.stExpander {
        border: none !important;
        box-shadow: none !important;
        background-color: transparent !important; /* 确保背景透明 */
    }
    div.stExpander > div:first-child {
        border: none !important;
        box-shadow: none !important;
        padding: 0.5rem 0rem; /* 调整expander标题的内边距 */
    }
    div.stExpander > div:first-child:hover {
        background-color: rgba(0, 0, 0, 0.03) !important; /* 悬停时有点背景色 */
    }
    </style>
    """, unsafe_allow_html=True)

    # 顶部布局：标题、刷新按钮、邮件数量设置在同一行
    # 调整列宽比例以更好地对齐和紧凑显示
    title_col, button_col, num_input_col = st.columns([3, 0.5, 1.2]) # 再次微调列宽比例
    
    with title_col:
        # 使用markdown和h3标签调整标题大小和位置，并添加Gmail图标
        # 增加margin-top使标题下移，调整字体大小
        st.markdown("<h3 style=\"margin-top: 0.4rem; margin-bottom: 0rem; font-size: 2.0rem;\"><img src=\"https://www.google.com/gmail/about/static/images/logo-gmail.png\" style=\"height: 32px; vertical-align: middle; margin-right: 12px;\">Gmail验证码查看器</h3>", unsafe_allow_html=True)
        
    with button_col:
        # 调整垂直位置，使其与标题中心对齐
        st.markdown("<div style=\"height: 0.8rem; display: flex; justify-content: center; align-items: center;\">", unsafe_allow_html=True) 
        if st.button("🔄", help="刷新邮件列表", key="refresh_button"):
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
            
    with num_input_col:
        # 调整垂直位置，使其与标题中心对齐
        st.markdown("<div style=\"height: 0.6rem;\"></div>", unsafe_allow_html=True) # 保持较小的高度
        num_emails_to_fetch = st.number_input(
            "显示邮件数量",
            min_value=1,
            max_value=50,
            value=10,
            step=1,
            help="设置要从Gmail获取的最近邮件数量。",
            key="num_emails_input"
        )
    
    st.subheader("最近的邮件")
            
    try:
        service = get_gmail_service()
        if service is None:
            return
            
        emails = get_recent_emails(service, max_results=num_emails_to_fetch)
        
        if not emails:
            st.info("在最近的邮件中未找到任何邮件。")
        else:
            for email_data in emails: # 更改循环变量名以避免冲突
                code_status = f"验证码：**{email_data['code']}**" if email_data['code'] else "验证码：未识别"
                # 调整标题格式，使其更紧凑，并避免视觉上的"分割"
                expander_header = f"**{email_data['subject']}** - {email_data['date']} - {code_status}"
                
                with st.expander(expander_header):
                    st.markdown(email_data['body'], unsafe_allow_html=True) # 改回使用st.markdown来显示HTML内容
                # 移除每封邮件下方的分割线 (此处不添加st.markdown("---"))
    
    except Exception as e:
        st.error(f"发生错误: {str(e)}")

if __name__ == "__main__":
    main() 