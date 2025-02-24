import os
from dotenv import load_dotenv
from app import app

# 加载开发环境配置
load_dotenv('.env.development')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=True, port=port)
