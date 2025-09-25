from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# 首页
@app.route("/")
def index():
    text = request.args.get('text')
    return "<h1>testestestHello, Flask!</h1>" + text

# 带参数的 GET 请求
@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    return f"<h2>Hello, {name}!</h2>"

# JSON 返回
@app.route("/api/data")
def api_data():
    data = {"status": "success", "message": "This is JSON response"}
    return jsonify(data)

# POST 请求
@app.route("/api/echo", methods=["POST"])
def api_echo():
    json_data = request.get_json()
    return jsonify({"you_sent": json_data})

# 简单的模板渲染
@app.route("/template")
def template_demo():
    template = """
    <html>
      <head><title>Flask Template</title></head>
      <body>
        <h1>Hello {{ name }}</h1>
      </body>
    </html>
    """
    return render_template_string(template, name="Flask User")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
