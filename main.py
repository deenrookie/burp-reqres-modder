# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener


# 所有Burp插件都必须实现IBurpExtender接口
class BurpExtender(IBurpExtender, IHttpListener):

    # 实现IBurpExtender接口的registerExtenderCallbacks方法
    def registerExtenderCallbacks(self, callbacks):
        # 保存callbacks对象的引用，以便后续使用
        self._callbacks = callbacks

        # 获取Burp的辅助方法对象
        self._helpers = callbacks.getHelpers()

        # 设置插件名称
        callbacks.setExtensionName("Simple Test Replacer")

        # 注册一个HTTP监听器，这样我们的插件就能处理HTTP请求和响应了
        callbacks.registerHttpListener(self)

        print("Simple Test Replacer extension has been loaded.")
        print("Author: Gemini")
        print("Function: Replaces 'test' with an empty string in requests and responses.")

    # 实现IHttpListener接口的processHttpMessage方法
    # Burp Proxy处理的每个HTTP消息都会调用此方法
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # messageIsRequest是一个布尔值，为True表示是请求，为False表示是响应
        if messageIsRequest:
            self.process_request(messageInfo)
        else:
            self.process_response(messageInfo)

    def process_request(self, messageInfo):
        """处理HTTP请求"""

        # 使用辅助方法分析请求，获取请求的详细信息（如headers, body等）
        requestInfo = self._helpers.analyzeRequest(messageInfo)

        # 获取请求头
        headers = list(requestInfo.getHeaders())

        # 获取请求体在整个请求中的偏移量
        bodyOffset = requestInfo.getBodyOffset()

        # 获取请求的原始字节流
        requestBytes = messageInfo.getRequest()

        # 提取请求体
        bodyBytes = requestBytes[bodyOffset:]

        # 使用Burp辅助方法将请求体从字节转换为字符串
        bodyStr = self._helpers.bytesToString(bodyBytes)

        # 检查 'test' 是否在请求体中
        if 'test' in bodyStr:
            # 替换 'test' 为空字符串
            modifiedBodyStr = bodyStr.replace('test', '')

            # 使用Burp辅助方法将修改后的请求体转回字节
            modifiedBodyBytes = self._helpers.stringToBytes(modifiedBodyStr)

            # 使用辅助方法构建一个新的HTTP请求
            newRequestBytes = self._helpers.buildHttpMessage(headers, modifiedBodyBytes)

            # 更新当前请求为我们修改后的请求
            messageInfo.setRequest(newRequestBytes)
            print("Modified a request: Replaced 'test' in request body.")

    def process_response(self, messageInfo):
        """处理HTTP响应"""

        # 使用辅助方法分析响应
        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())

        # 获取响应头
        headers = list(responseInfo.getHeaders())

        # 获取响应体在整个响应中的偏移量
        bodyOffset = responseInfo.getBodyOffset()

        # 获取响应的原始字节流
        responseBytes = messageInfo.getResponse()

        # 提取响应体
        bodyBytes = responseBytes[bodyOffset:]

        # 使用Burp辅助方法将响应体从字节转换为字符串
        bodyStr = self._helpers.bytesToString(bodyBytes)

        # 检查 'test' 是否在响应体中
        if 'test' in bodyStr:
            # 替换 'test' 为空字符串
            modifiedBodyStr = bodyStr.replace('test', '')

            # 使用Burp辅助方法将修改后的响应体转回字节
            modifiedBodyBytes = self._helpers.stringToBytes(modifiedBodyStr)

            # 使用辅助方法构建一个新的HTTP响应
            newResponseBytes = self._helpers.buildHttpMessage(headers, modifiedBodyBytes)

            # 更新当前响应为我们修改后的响应
            messageInfo.setResponse(newResponseBytes)
            print("Modified a response: Replaced 'test' in response body.")

