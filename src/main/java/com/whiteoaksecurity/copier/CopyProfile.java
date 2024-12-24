package com.whiteoaksecurity.copier;

import burp.api.montoya.http.message.HttpMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.whiteoaksecurity.copier.Utils.*;


public class CopyProfile {
	public static final String REQUEST_DATA = "requestData";
	public static final String RESPONSE_DATA = "responseData";
	public static final String NONE_CONTENT = "NONE CONTENT";
	public static final String SPILT = "\r\n\r\n";
	public static final String CONCAT = "\n====================================================\n";

	private String name;
	private RequestRulesTableModel requestRulesTableModel;
	private ResponseRulesTableModel responseRulesTableModel;
	private boolean updateRequestContentLength = false;
	private boolean updateResponseContentLength = false;

	@JsonCreator
	public CopyProfile(@JsonProperty("name") String name) {
		this.name = name;
		this.requestRulesTableModel = new RequestRulesTableModel();
		this.responseRulesTableModel = new ResponseRulesTableModel();
	}
	
	@Override
	public String toString() {
		return this.name;
	}
	
	public String getName() {
		return this.name;
	}
	
	public boolean getUpdateRequestContentLength() {
		return this.updateRequestContentLength;
	}
	
	public boolean getUpdateResponseContentLength() {
		return this.updateResponseContentLength;
	}
	
	@JsonProperty("requestRules")
	public RequestRulesTableModel getRequestRulesTableModel() {
		return this.requestRulesTableModel;
	}
	
	@JsonProperty("responseRules")
	public ResponseRulesTableModel getResponseRulesTableModel() {
		return this.responseRulesTableModel;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public void setUpdateRequestContentLength(boolean update) {
		this.updateRequestContentLength = update;
	}
	
	public void setUpdateResponseContentLength(boolean update) {
		this.updateResponseContentLength = update;
	}

	public String getFirstLine(HttpMessage httpMessage) {
		String[] entireResponseAsArray = (new String(httpMessage.toByteArray().getBytes(), StandardCharsets.UTF_8)).lines().toList().toArray(new String[0]);
		if (entireResponseAsArray.length > 0) {
			return entireResponseAsArray[0];
		} else {
			return null;
		}
	}

	public HttpRequestResponse replace(HttpRequestResponse requestResponse, boolean replaceRequest, boolean replaceResponse) {
		ArrayList<HttpRequestResponse> temp = new ArrayList<>();
		temp.add(requestResponse);
		return this.replace(temp, replaceRequest, replaceResponse).get(0);
	}

	public ArrayList<HttpRequestResponse> replace(List<HttpRequestResponse> requestResponses, boolean replaceRequest, boolean replaceResponse) {
		ArrayList<HttpRequestResponse> modified = new ArrayList<>();

		//请求修改规则
		ArrayList<Rule> requestReplaceRules = getEnabledReplaceRules(this.getRequestRulesTableModel().getData());
		//响应修改规则
		ArrayList<Rule> responseReplaceRules = getEnabledReplaceRules(this.getResponseRulesTableModel().getData());

		for (HttpRequestResponse httpRequestResponse : requestResponses) {

			HttpRequest httpRequest = httpRequestResponse.request();
			boolean isHTTP2 = false;

			// Convert HTTP/2 to HTTP/1.1 while performing match / replace rules.
			if (httpRequest.httpVersion() != null && httpRequest.httpVersion().equals("HTTP/2")) {
				isHTTP2 = true;
				httpRequest = HttpRequest.httpRequest(httpRequest.toByteArray());
			}

			Integer requestContentLength = null;
			for (HttpHeader h : httpRequest.headers()) {
				if (h.name().trim().equalsIgnoreCase("Content-Length")) {
					try {
						requestContentLength = Integer.parseInt(h.value().trim());
					} catch (NumberFormatException e) {}

					break;
				}
			}

			// HTTP/2 responses appear to get treated the same way as HTTP/1.1 by Burp.
			HttpResponse httpResponse = httpRequestResponse.response();

			if (replaceRequest) {
				for (Rule requestRule : requestReplaceRules) {
					try {
						String entireRequest = httpRequest.toByteArray().toString();
						switch (requestRule.getLocation()) {
							// Entire Request
							case 0 -> {
								httpRequest = HttpRequest.httpRequest(httpRequest.httpService(), requestRule.getPattern().matcher(entireRequest).replaceAll(requestRule.getReplace()));
								break;
							}
							// Request Line
							case 1 -> {
								String[] entireRequestAsArray = entireRequest.lines().toList().toArray(new String[0]);
								if (entireRequestAsArray.length > 0) {
									entireRequestAsArray[0] = requestRule.getPattern().matcher(entireRequestAsArray[0]).replaceAll(requestRule.getReplace());
								} else {
									break;
								}

								httpRequest = HttpRequest.httpRequest(httpRequest.httpService(), String.join("\r\n", entireRequestAsArray));
								break;
							}
							// Request URL Param
							case 2 -> {
								List<ParsedHttpParameter> params = httpRequest.parameters();
								List<HttpParameter> updatedParams = new ArrayList<>();
								for (ParsedHttpParameter param : params) {
									if (param.type().equals(HttpParameterType.URL)) {
										String paramString = requestRule.getPattern().matcher(entireRequest.substring(param.nameOffsets().startIndexInclusive(), param.valueOffsets().endIndexExclusive())).replaceAll(requestRule.getReplace());
										// If param is now empty, we don't add it back to the request.
										if (!paramString.isEmpty()) {
											String[] keyValue = paramString.split("=", 2);
											if (keyValue.length == 2) {
												updatedParams.add(HttpParameter.urlParameter(keyValue[0], keyValue[1]));
											} else if (keyValue.length == 1) {
												updatedParams.add(HttpParameter.urlParameter(keyValue[0], ""));
											}
										}
									} else {
										updatedParams.add(param);
									}

									// We have to remove each param individually and then add them back later for some reason.
									httpRequest = httpRequest.withRemovedParameters(param);
								}
								httpRequest = httpRequest.withAddedParameters(updatedParams);
								break;
							}
							// Request URL Param Name
							case 3 -> {
								List<ParsedHttpParameter> params = httpRequest.parameters();
								List<HttpParameter> updatedParams = new ArrayList<>();
								for (ParsedHttpParameter param : params) {
									if (param.type().equals(HttpParameterType.URL)) {
										String paramName = requestRule.getPattern().matcher(param.name()).replaceAll(requestRule.getReplace());
										// If param name is now empty, we don't add it back to the request.
										if (!paramName.isEmpty()) {
											updatedParams.add(HttpParameter.urlParameter(paramName, param.value()));
										}
									} else {
										updatedParams.add(param);
									}

									// We have to remove each param individually and then add them back later for some reason.
									httpRequest = httpRequest.withRemovedParameters(param);
								}
								httpRequest = httpRequest.withAddedParameters(updatedParams);
								break;
							}
							// Request URL Param Value
							case 4 -> {
								List<ParsedHttpParameter> params = httpRequest.parameters();
								List<HttpParameter> updatedParams = new ArrayList<>();
								for (ParsedHttpParameter param : params) {
									if (param.type().equals(HttpParameterType.URL)) {
										String paramValue = requestRule.getPattern().matcher(param.value()).replaceAll(requestRule.getReplace());
										updatedParams.add(HttpParameter.urlParameter(param.name(), paramValue));
									} else {
										updatedParams.add(param);
									}

									// We have to remove each param individually and then add them back later for some reason.
									httpRequest = httpRequest.withRemovedParameters(param);
								}
								httpRequest = httpRequest.withAddedParameters(updatedParams);
								break;
							}
							// Request Headers
							case 5 -> {
								String headers = "";
								if (httpRequest.bodyOffset() > 0){
									headers = entireRequest.substring(0, httpRequest.bodyOffset());
								} else if (entireRequest.contains(SPILT)){
									System.out.println(String.format("获取请求头发生错误: bodyOffset=[%s] 尝试切割方案获取请求头", httpRequest.bodyOffset()));
										headers = entireRequest.split(SPILT,2)[0];
								} else {
										System.out.println("获取请求头发生错误: 当前不包含(换行*2)特征 跳过本次请求头替换");
										break;
								}

								String linebreak = "\r\n";
								if (!headers.contains(linebreak)) {
									linebreak = "\n";
								}
								headers = requestRule.getPattern().matcher(headers.strip() + linebreak).replaceAll(requestRule.getReplace());
								// Remove blank lines.
								while (headers.contains("\r\n\r\n") || headers.contains("\n\n")) {
									headers = headers.replaceAll("\r\n\r\n", "\r\n").replaceAll("\n\n", "\n");
								}

								httpRequest = HttpRequest.httpRequest(httpRequest.httpService(), headers + linebreak + httpRequest.bodyToString());
								break;
							}
							// Request Header
							case 6 -> {
								List<HttpHeader> headers = httpRequest.headers();
								List<HttpHeader> updatedHeaders = new ArrayList<>();
								for (HttpHeader header : headers) {
									String headerString = requestRule.getPattern().matcher(header.toString()).replaceAll(requestRule.getReplace());
									// If header is now empty, we don't add it back into the request.
									if (!headerString.isEmpty()) {
										// If header has changed, update the header in the request.
										if (!headerString.equals(header.toString())) {
											updatedHeaders.add(HttpHeader.httpHeader(headerString));
										} else {
											updatedHeaders.add(header);
										}
									}

									// We have to remove each header individually and then add them back later to preserve the order.
									httpRequest = httpRequest.withRemovedHeader(header);
								}

								for (HttpHeader header : updatedHeaders) {
									httpRequest = httpRequest.withAddedHeader(header);
								}
								break;
							}
							// Request Header Name
							case 7 -> {
								List<HttpHeader> headers = httpRequest.headers();
								List<HttpHeader> updatedHeaders = new ArrayList<>();
								for (HttpHeader header : headers) {
									String headerNameString = requestRule.getPattern().matcher(header.name()).replaceAll(requestRule.getReplace());
									// If header name is now empty, we don't add it back into the request.
									if (!headerNameString.isEmpty()) {
										// If header name has changed, update the header in the request.
										if (!headerNameString.equals(header.name())) {
											updatedHeaders.add(HttpHeader.httpHeader(headerNameString, header.value()));
										} else {
											updatedHeaders.add(header);
										}
									}

									// We have to remove each header individually and then add them back later to preserve the order.
									httpRequest = httpRequest.withRemovedHeader(header);
								}

								for (HttpHeader header : updatedHeaders) {
									httpRequest = httpRequest.withAddedHeader(header);
								}
								break;
							}
							// Request Header Value
							case 8 -> {
								List<HttpHeader> headers = httpRequest.headers();
								for (HttpHeader header : headers) {
									String headerValueString = requestRule.getPattern().matcher(header.value()).replaceAll(requestRule.getReplace());

									// If header value has changed, update the header in the request
									// Empty values are technically OK.
									if (!headerValueString.equals(header.value())) {
										httpRequest = httpRequest.withUpdatedHeader(header.name(), headerValueString);
									}
								}
								break;
							}
							// Request Body
							case 9 -> {
								httpRequest = httpRequest.withBody(requestRule.getPattern().matcher(httpRequest.bodyToString()).replaceAll(requestRule.getReplace()));
								// Since the Content-Length header gets updated automatically, we should reset it unless the user has
								// specified otherwise.
								if (!this.updateRequestContentLength && requestContentLength != null) {
									httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
								}
								break;
							}
							// Request Body Params
							case 10 -> {
								List<ParsedHttpParameter> params = httpRequest.parameters();
								List<HttpParameter> updatedParams = new ArrayList<>();
								for (ParsedHttpParameter param : params) {
									if (param.type().equals(HttpParameterType.BODY))
									{
										String paramString = requestRule.getPattern().matcher(entireRequest.substring(param.nameOffsets().startIndexInclusive(), param.valueOffsets().endIndexExclusive())).replaceAll(requestRule.getReplace());
										// If param is now empty, we don't add it back to the request.
										if (!paramString.isEmpty()) {
											String[] keyValue = paramString.split("=", 2);
											if (keyValue.length == 2) {
												updatedParams.add(HttpParameter.bodyParameter(keyValue[0], keyValue[1]));
											} else if (keyValue.length == 1) {
												updatedParams.add(HttpParameter.bodyParameter(keyValue[0], ""));
											}
										}
									} else {
										updatedParams.add(param);
									}

									// We have to remove each param individually and then add them back later for some reason.
									httpRequest = httpRequest.withRemovedParameters(param);
								}

								httpRequest = httpRequest.withAddedParameters(updatedParams);

								// Since the Content-Length header gets updated automatically, we should reset it unless the user has
								// specified otherwise.
								if (!this.updateRequestContentLength && requestContentLength != null) {
									httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
								}
								break;
							}
							// Request Body Param Name
							case 11 -> {
								List<ParsedHttpParameter> params = httpRequest.parameters();
								List<HttpParameter> updatedParams = new ArrayList<>();
								for (ParsedHttpParameter param : params) {
									if (param.type().equals(HttpParameterType.BODY)) {
										String paramName = requestRule.getPattern().matcher(param.name()).replaceAll(requestRule.getReplace());
										// If param name is now empty, we don't add it back to the request.
										if (!paramName.isEmpty()) {
											updatedParams.add(HttpParameter.bodyParameter(paramName, param.value()));
										}
									} else {
										updatedParams.add(param);
									}

									// We have to remove each param individually and then add them back later for some reason.
									httpRequest = httpRequest.withRemovedParameters(param);
								}

								httpRequest = httpRequest.withAddedParameters(updatedParams);

								// Since the Content-Length header gets updated automatically, we should reset it unless the user has
								// specified otherwise.
								if (!this.updateRequestContentLength && requestContentLength != null) {
									httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
								}
								break;
							}
							// Request Body Param Value
							case 12 -> {
								List<ParsedHttpParameter> params = httpRequest.parameters();
								List<HttpParameter> updatedParams = new ArrayList<>();
								for (ParsedHttpParameter param : params) {
									if (param.type().equals(HttpParameterType.BODY)) {
										String paramValue = requestRule.getPattern().matcher(param.value()).replaceAll(requestRule.getReplace());
										updatedParams.add(HttpParameter.bodyParameter(param.name(), paramValue));
									} else {
										updatedParams.add(param);
									}

									// We have to remove each param individually and then add them back later for some reason.
									httpRequest = httpRequest.withRemovedParameters(param);
								}
								httpRequest = httpRequest.withAddedParameters(updatedParams);

								// Since the Content-Length header gets updated automatically, we should reset it unless the user has
								// specified otherwise.
								if (!this.updateRequestContentLength && requestContentLength != null) {
									httpRequest = httpRequest.withUpdatedHeader("Content-Length", requestContentLength.toString());
								}
								break;
							}

							default -> {break;}
						}
					} catch (IndexOutOfBoundsException ex) {
						Logger.getLogger().logToError("An exception occurred when trying to execute a copy rule on a request: " + ex.getMessage());
						Logger.getLogger().logToError("This usually means your replacement referenced a group which didn't exist in the match.");
						Logger.getLogger().logToError("Replacement: " + requestRule.toString(requestRulesTableModel.getLocations()) + "\n");
					}
				}
			}

			// Sometimes (e.g. in a Repeater tab) there won't be a response.
			if (replaceResponse && httpResponse != null) {

				Integer responseContentLength = null;
				for (HttpHeader h : httpResponse.headers()) {
					if (h.name().trim().equalsIgnoreCase("Content-Length")) {
						try {
							responseContentLength = Integer.parseInt(h.value().trim());
						} catch (NumberFormatException e) {}

						break;
					}
				}


				// Figure out what line breaks are used for headers.
				String entireResponseUTF8 = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
				String headersString = entireResponseUTF8.substring(0, httpResponse.bodyOffset());
				String linebreak = "\r\n";
				if (!headersString.contains(linebreak)) {
					linebreak = "\n";
				}

				for (Rule responseRule : responseReplaceRules) {
					try {
						entireResponseUTF8 = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
						switch (responseRule.getLocation()) {
							// Entire Response
							case 0 -> {
								httpResponse = HttpResponse.httpResponse(responseRule.getPattern().matcher(entireResponseUTF8).replaceAll(responseRule.getReplace()));
								break;
							}
							// Response Status Line
							case 1 -> {
								String[] entireResponseAsArray = entireResponseUTF8.lines().toList().toArray(new String[0]);
								if (entireResponseAsArray.length > 0) {
									entireResponseAsArray[0] = responseRule.getPattern().matcher(entireResponseAsArray[0]).replaceAll(responseRule.getReplace());
								} else {
									break;
								}
								httpResponse = HttpResponse.httpResponse(String.join("\r\n", entireResponseAsArray));
								break;
							}
							// Response Headers
							case 2 -> {
								String statusLine = getFirstLine(httpResponse);
								if (statusLine == null) {
									break;
								}

								List<HttpHeader> headers = httpResponse.headers();
								StringBuilder sb = new StringBuilder();
								for (HttpHeader header : headers) {
									sb.append(header.toString()).append(linebreak);
								}

								String updatedHeaders = responseRule.getPattern().matcher(sb.toString()).replaceAll(responseRule.getReplace());
								while (updatedHeaders.contains("\r\n\r\n") || updatedHeaders.contains("\n\n")) {
									updatedHeaders = updatedHeaders.replace("\r\n\r\n", "\r\n").replace("\n\n", "\n");
								}

								httpResponse = HttpResponse.httpResponse(statusLine + linebreak + updatedHeaders + linebreak + httpResponse.bodyToString());
								break;
							}
							// Response Header
							case 3 -> {
								String statusLine = getFirstLine(httpResponse);
								if (statusLine == null) {
									break;
								}

								List<HttpHeader> headers = httpResponse.headers();
								List<HttpHeader> updatedHeaders = new ArrayList<>();
								for (HttpHeader header : headers) {
									String headerString = responseRule.getPattern().matcher(header.toString()).replaceAll(responseRule.getReplace());
									// If header is now empty, we don't add it back into the request.
									if (!headerString.isEmpty()) {
										// If header has changed, update the header in the request.
										if (!headerString.equals(header.toString())) {
											updatedHeaders.add(HttpHeader.httpHeader(headerString));
										} else {
											updatedHeaders.add(header);
										}
									}
								}

								StringBuilder sb = new StringBuilder();
								for (HttpHeader header : updatedHeaders) {
									sb.append(header.toString()).append(linebreak);
								}

								httpResponse = HttpResponse.httpResponse(statusLine + linebreak + sb.toString() + linebreak + httpResponse.bodyToString());
								break;
							}
							// Response Header Name
							case 4 -> {
								String statusLine = getFirstLine(httpResponse);
								if (statusLine == null) {
									break;
								}

								List<HttpHeader> headers = httpResponse.headers();
								List<HttpHeader> updatedHeaders = new ArrayList<>();
								for (HttpHeader header : headers) {
									String headerNameString = responseRule.getPattern().matcher(header.name()).replaceAll(responseRule.getReplace());
									// If header name is now empty, we don't add it back into the request.
									if (!headerNameString.isEmpty()) {
										// If header name has changed, update the header in the request.
										if (!headerNameString.equals(header.name())) {
											updatedHeaders.add(HttpHeader.httpHeader(headerNameString, header.value()));
										} else {
											updatedHeaders.add(header);
										}
									}
								}

								StringBuilder sb = new StringBuilder();
								for (HttpHeader header : updatedHeaders) {
									sb.append(header.toString()).append(linebreak);
								}

								httpResponse = HttpResponse.httpResponse(statusLine + linebreak + sb.toString() + linebreak + httpResponse.bodyToString());
								break;
							}
							// Response Header Value
							case 5 -> {
								String statusLine = getFirstLine(httpResponse);
								if (statusLine == null) {
									break;
								}

								List<HttpHeader> headers = httpResponse.headers();
								List<HttpHeader> updatedHeaders = new ArrayList<>();
								for (HttpHeader header : headers) {
									String headerValueString = responseRule.getPattern().matcher(header.value()).replaceAll(responseRule.getReplace());

									// If header value has changed, update the header in the request
									// Empty values are technically OK.
									if (!headerValueString.equals(header.value())) {
										updatedHeaders.add(HttpHeader.httpHeader(header.name(), headerValueString));
									} else {
										updatedHeaders.add(header);
									}
								}

								StringBuilder sb = new StringBuilder();
								for (HttpHeader header : updatedHeaders) {
									sb.append(header.toString()).append(linebreak);
								}

								httpResponse = HttpResponse.httpResponse(statusLine + linebreak + sb.toString() + linebreak + httpResponse.bodyToString());
								break;
							}
							// Response Body
							case 6 -> {
								httpResponse = httpResponse.withBody(responseRule.getPattern().matcher(httpResponse.bodyToString()).replaceAll(responseRule.getReplace()));

								if (!this.updateResponseContentLength && responseContentLength != null) {
									httpResponse = httpResponse.withUpdatedHeader("Content-Length", responseContentLength.toString());
								}
								break;
							}

							default -> {break;}
						}
					} catch (IndexOutOfBoundsException ex) {
						Logger.getLogger().logToError("An exception occurred when trying to execute a copy rule on a response: " + ex.getMessage());
						Logger.getLogger().logToError("This usually means your replacement referenced a group which didn't exist in the match.");
						Logger.getLogger().logToError("Replacement: " + responseRule.toString(responseRulesTableModel.getLocations()) + "\n");
					}
				}
			}

			// If request was HTTP/2 originally, convert back.
			if (isHTTP2) {
				// Need to build URL param list manually.
				ArrayList<HttpParameter> queryParams = new ArrayList<HttpParameter>();
				for (HttpParameter p : httpRequest.parameters()) {
					if (p.type().equals(HttpParameterType.URL)) {
						queryParams.add(p);
					}
				}

				HttpRequest http2 = HttpRequest.http2Request(httpRequest.httpService(), httpRequest.headers(), httpRequest.body());
				// Make sure the request includes the correct method, path, and URL params.
				httpRequest = http2.withMethod(httpRequest.method()).withPath(httpRequest.path()).withRemovedParameters(queryParams).withAddedParameters(queryParams);
			}

			modified.add(HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse));
		}

		return modified;
	}

	public Map<String, String> copyLocateDateSimple(HttpRequestResponse httpRequestResponse,
													boolean copyRequest, boolean copyResponse,
													Rule requestRule, Rule responseRule) {
		// 创建一个 Map 对象来存储键值对
		Map<String, String> map = new LinkedHashMap<>();

		String requestReturn = NONE_CONTENT;
		if (copyRequest) {
			HttpRequest httpRequest = httpRequestResponse.request();
			if (httpRequest != null){
				//默认返回全文
				requestReturn = new String(httpRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
				//勾选只保存已选定的位置,只保留指定的位置的数据
				if (requestRule != null && requestRule.isLocateRule()){
					try {
						String entireRequest = httpRequest.toByteArray().toString();
						switch (requestRule.getLocation()) {
							// Request 保留全部请求体
							case 0 -> {
								//默认返回全文
								break;
							}
							// Request line 保留请求行
							case 1 -> {
								String[] entireRequestAsArray = entireRequest.lines().toList().toArray(new String[0]);
								requestReturn = entireRequestAsArray[0];
								break;
							}
							// Request Headers 请求头
							case 5 -> {
								requestReturn = getRequestHeaders(httpRequest);
								break;
							}
							// Request Body 请求体
							case 9 -> {
								requestReturn = ByteArrayToString(httpRequest.body(), StandardCharsets.UTF_8);
								break;
							}
							default -> {
								System.out.println("提示：该选项未精确实现, 返回请求行+请求体 ...");
								String[] entireRequestAsArray = entireRequest.lines().toList().toArray(new String[0]);
								String requestLine = entireRequestAsArray[0];
								String requestBody = ByteArrayToString(httpRequest.body(), StandardCharsets.UTF_8);
								requestReturn = (requestLine + "\n" + requestBody).trim();
								break;
							}
						}
					} catch (IndexOutOfBoundsException ex) {
						Logger.getLogger().logToError(String.format("根据规则[%s]提取请求信息发生错误: [%s]", requestRule.toString(requestRulesTableModel.getLocations()), ex.getMessage()));
					}
				}
			}

			//对结果进行base64编码
			requestReturn = base64EncodeStrWithCheck(requestReturn, requestRule.isEnabledBase64());

			map.put(REQUEST_DATA, requestReturn);
		}

		String responseReturn = NONE_CONTENT;
		if (copyResponse) {
			HttpResponse httpResponse = httpRequestResponse.response();
			if (httpResponse != null){
				//获取全部内容数据
				String entireResponseUTF8 = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
				//默认返回全文
				responseReturn = entireResponseUTF8;

				if (responseRule != null && responseRule.isLocateRule()){
					try {
						switch (responseRule.getLocation()) {
							// Response
							case 0 -> {
								//默认返回全文
								break;
							}
							// Response Status Line 响应状态行
							case 1 -> {
								String[] entireResponseAsArray = entireResponseUTF8.lines().toList().toArray(new String[0]);
								responseReturn = entireResponseAsArray[0];
								break;
							}
							// Response Headers
							case 2 -> {
								responseReturn = getResponseHeaders(httpResponse);
								break;
							}
							// Response Body
							case 6 -> {
								//responseReturn = httpResponse.bodyToString(); //存在乱码问题
								responseReturn= ByteArrayToString(httpResponse.body(), StandardCharsets.UTF_8);
								break;
							}

							default -> {
								System.out.println("提示：该选项未精确实现, 返回响应行+响应体 ...");
								String[] entireResponseAsArray = entireResponseUTF8.lines().toList().toArray(new String[0]);
								String responseLine = entireResponseAsArray[0];
								String responseBody = ByteArrayToString(httpResponse.body(), StandardCharsets.UTF_8);
								responseReturn = (responseLine + "\n" + responseBody).trim();
								break;
							}
						}
					} catch (IndexOutOfBoundsException ex) {
						Logger.getLogger().logToError(String.format("根据规则[%s]提取响应信息发生错误: [%s]", responseRule.toString(responseRulesTableModel.getLocations()), ex.getMessage()));
					}
				}
			}

			//对结果进行base64编码
			responseReturn = base64EncodeStrWithCheck(responseReturn, responseRule.isEnabledBase64());
			map.put(RESPONSE_DATA, responseReturn);
		}

		return map;
	}




	private Map<String, String> copyLocateDateJson(HttpRequestResponse httpRequestResponse,
												   boolean copyRequest, boolean copyResponse,
												   ArrayList<Rule> requestLocateRules,
												   ArrayList<Rule> responseLocateRules) {
		// 创建一个 Map 对象来存储键值对
		Map<String, String> map = new LinkedHashMap<>();

		if (copyRequest) {
			HttpRequest httpRequest = httpRequestResponse.request();
			if (httpRequest != null){
				//默认返回全文 不需要编码的全文
				if(requestLocateRules == null || requestLocateRules.isEmpty()){
					String requestAll = new String(httpRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
					requestAll = base64EncodeStrWithCheck(requestAll, false);
					map.put("requestAll", requestAll);
				}
				else { //保留指定的部位的数据
					for (Rule requestRule: requestLocateRules) {
						try {
							final String entireRequest = httpRequest.toByteArray().toString();
							switch (requestRule.getLocation()) {
								case 0 -> {
									// Request 保留全部请求体
									String requestAll = new String(httpRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
									requestAll = base64EncodeStrWithCheck(requestAll, requestRule.isEnabledBase64());
									map.put("requestAll", requestAll);
									break;
								}
								// Request line 保留请求行
								case 1 -> {
									String[] entireRequestAsArray = entireRequest.lines().toList().toArray(new String[0]);
									String requestLine = entireRequestAsArray[0];
									requestLine = base64EncodeStrWithCheck(requestLine, requestRule.isEnabledBase64());
									map.put("requestLine", requestLine);
									break;
								}
								// Request Headers 请求头
								case 5 -> {
									String requestHeaders = getRequestHeaders(httpRequest);
									requestHeaders = base64EncodeStrWithCheck(requestHeaders, requestRule.isEnabledBase64());
									map.put("requestHeaders", requestHeaders);
									break;
								}
								// Request Body 请求体
								case 9 -> {
									String requestBody = ByteArrayToString(httpRequest.body(), StandardCharsets.UTF_8);
									requestBody = base64EncodeStrWithCheck(requestBody, requestRule.isEnabledBase64());
									map.put("requestBody", requestBody);
									break;
								}
								default -> {
									System.out.println("提示：该选项未精确实现, 返回请求行+请求体 ...");
									String[] entireRequestAsArray = entireRequest.lines().toList().toArray(new String[0]);
									String requestLine = entireRequestAsArray[0];
									String requestBody = ByteArrayToString(httpRequest.body(), StandardCharsets.UTF_8);
									map.put("requestLine", requestLine);
									map.put("requestBody", requestBody);
									break;
								}
							}
						} catch (IndexOutOfBoundsException ex) {
							Logger.getLogger().logToError(String.format("根据规则[%s]提取请求信息发生错误: [%s]", requestRule.toString(requestRulesTableModel.getLocations()), ex.getMessage()));

						}
					}

				}
			}
		}

		if (copyResponse) {
			HttpResponse httpResponse = httpRequestResponse.response();
			if (httpResponse != null){
				//默认返回全文 不需要编码的全文
				if(responseLocateRules == null || responseLocateRules.isEmpty()){
					String responseAll = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
					responseAll = base64EncodeStrWithCheck(responseAll, false);
					map.put("responseAll", responseAll);
				}
				else { //保留指定的部位的数据
					for (Rule responseRule: responseLocateRules) {
						try {
							String entireResponse = httpResponse.toByteArray().toString();

							switch (responseRule.getLocation()) {
								// Response
								case 0 -> {
									String responseAll = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
									responseAll = base64EncodeStrWithCheck(responseAll, responseRule.isEnabledBase64());
									map.put("responseAll", responseAll);
									break;
								}
								// Response Status Line 响应状态行
								case 1 -> {
									String[] entireResponseAsArray = (new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8)).lines().toList().toArray(new String[0]);
									String responseLine = entireResponseAsArray[0];
									responseLine = base64EncodeStrWithCheck(responseLine, responseRule.isEnabledBase64());
									map.put("responseLine", responseLine);
									break;
								}
								// Response Headers
								case 2 -> {
									String responseHeaders = getResponseHeaders(httpResponse);
									responseHeaders = base64EncodeStrWithCheck(responseHeaders, responseRule.isEnabledBase64());
									map.put("responseHeaders", responseHeaders);
									break;
								}
								// Response Body
								case 6 -> {
									String responseBody = ByteArrayToString(httpResponse.body(), StandardCharsets.UTF_8);
									responseBody = base64EncodeStrWithCheck(responseBody, responseRule.isEnabledBase64());
									map.put("responseBody", responseBody);
									break;
								}

								default -> {
									System.out.println("提示：该选项未精确实现, 返回响应行+响应体 ...");
									String[] entireResponseAsArray = (new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8)).lines().toList().toArray(new String[0]);
									String responseLine = entireResponseAsArray[0];
									String responseBody = ByteArrayToString(httpResponse.body(), StandardCharsets.UTF_8);
									map.put("responseLine", responseLine);
									map.put("responseBody", responseBody);
									break;
								}
							}
						} catch (IndexOutOfBoundsException ex) {
							Logger.getLogger().logToError(String.format("根据规则[%s]提取响应信息发生错误: [%s]", responseRule.toString(responseRulesTableModel.getLocations()), ex.getMessage()));
						}
					}
				}
			}

		}

		return map;
	}


	/**
	 * 获取指定部位的数据
	 * @return
	 */
	public String copyLocateDate(List<HttpRequestResponse> httpRequestResponses, boolean copyRequest, boolean copyResponse) {
		StringBuilder modified = new StringBuilder();

		//copy替换功能目前只能支持一条规则的拷贝,获取最后一条规则用于提取指定位置,其他的规则用于替换,最好还是只有一条规则
		ArrayList<Rule> requestLocateRules = getEnabledLocateRules(this.getRequestRulesTableModel().getData());
		ArrayList<Rule> responseLocateRules = getEnabledLocateRules(this.getResponseRulesTableModel().getData());

		//没有找到任何提取规则时,忽略操作?
		if (requestLocateRules.isEmpty()&&responseLocateRules.isEmpty()){
			System.out.println("没有获取到任何开放的提取规则, 调用替换规则提取");
			requestLocateRules = fixReplaceRulesToLocateRules(getEnabledReplaceRules(this.getRequestRulesTableModel().getData()));
			responseLocateRules = fixReplaceRulesToLocateRules(getEnabledReplaceRules(this.getResponseRulesTableModel().getData()));
		}
		if (requestLocateRules.isEmpty() && responseLocateRules.isEmpty()){
			System.out.println("没有获取到任何开放的提取规则和修改规则, 返回Null");
			return null;
		}

		//分析是否调用Json格式输出 任何一个规则含有json格式要求就表示需要json格式
		Boolean isJsonMode = checkUseJsonFormat(listAddList(requestLocateRules, responseLocateRules));
		//System.out.println("Current is Json Mode: " + isJsonMode);

		if (!isJsonMode){
			//常规的字符串格式保存
			//System.out.println("注意: 当前Text模式 仅使用最后1条规则用于请求|响应位置提取");
			Rule requestLocateRule = getLastLocateRule(requestLocateRules);
			Rule responseLocateRule = getLastLocateRule(responseLocateRules);

			for (HttpRequestResponse httpRequestResponse : httpRequestResponses) {
				Map<String, String> copyLocateDateSimple = copyLocateDateSimple(httpRequestResponse, copyRequest, copyResponse, requestLocateRule, responseLocateRule);
				StringBuilder copyBuffer = new StringBuilder();
				if (copyRequest) { copyBuffer.append(copyLocateDateSimple.get(REQUEST_DATA)); }
				if (copyRequest && copyResponse) { copyBuffer.append("\n\n"); }
				if (copyResponse) { copyBuffer.append(copyLocateDateSimple.get(RESPONSE_DATA)); }
				modified.append(copyBuffer).append(CONCAT);
			}
		} else {
			//Json格式保存 应当支持更多复杂的内容
			for (HttpRequestResponse httpRequestResponse : httpRequestResponses) {
				Map<String, String> copyLocateDateJson = copyLocateDateJson(httpRequestResponse, copyRequest, copyResponse, requestLocateRules, responseLocateRules);
				String jsonString = null;
				try {
					jsonString = new ObjectMapper().writeValueAsString(copyLocateDateJson);
				} catch (JsonProcessingException e) {
					e.printStackTrace();
				}
				modified.append(jsonString).append(CONCAT);
			}
		}

		return modified.toString();
	}

}
