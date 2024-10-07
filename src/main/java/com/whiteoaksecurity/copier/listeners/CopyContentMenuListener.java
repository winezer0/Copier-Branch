package com.whiteoaksecurity.copier.listeners;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import com.whiteoaksecurity.copier.CopyProfile;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

public class CopyContentMenuListener implements ActionListener {

	private CopyProfile profile;
	private boolean copyRequest;
	private boolean copyResponse;
	private ContextMenuEvent contextEvent;
	
	public CopyContentMenuListener(CopyProfile profile, boolean copyRequest, boolean copyResponse, ContextMenuEvent contextEvent) {
		this.profile = profile;
		this.copyRequest = copyRequest;
		this.copyResponse = copyResponse;
		this.contextEvent = contextEvent;
	}
	
	@Override
	public void actionPerformed(ActionEvent actionEvent) {

		//整理所有选中的消息
		ArrayList<HttpRequestResponse> selectedRequestResponses = new ArrayList<>();

		//选中Proxy列表的多条消息
		if (!this.contextEvent.selectedRequestResponses().isEmpty()) {
			selectedRequestResponses.addAll(this.contextEvent.selectedRequestResponses());
		}
		//选中编辑框的消息
		else if (!this.contextEvent.messageEditorRequestResponse().isEmpty()) {
			//选中编辑框的消息
			HttpRequestResponse httpRequestResponse = this.contextEvent.messageEditorRequestResponse().get().requestResponse();
			selectedRequestResponses.add(httpRequestResponse);
		}

		//根据规则进行替换处理
		ArrayList<HttpRequestResponse> handledRequestResponses = this.profile.replace(selectedRequestResponses, this.copyRequest, this.copyResponse);

		//根据规则进行位置提取
		String copyBuffer = this.profile.copyLocateDate(handledRequestResponses, this.copyRequest, this.copyResponse);
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(copyBuffer), null);
	}

}
