package com.whiteoaksecurity.copier.listeners;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import com.whiteoaksecurity.copier.CopyProfile;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import static com.whiteoaksecurity.copier.UiUtils.*;

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
		//选择保存模式
		int saveOption = getSaveOption();
		String savePath = getFileOrDirToSavePath(saveOption);

		if (saveOption>-1 && savePath != null){
			//整理所有选中的消息
			ArrayList<HttpRequestResponse> selectedRequestResponses = new ArrayList<>();

			//选中Proxy列表的多条消息
			if (!this.contextEvent.selectedRequestResponses().isEmpty()) {
				selectedRequestResponses.addAll(this.contextEvent.selectedRequestResponses());
			} else if (!this.contextEvent.messageEditorRequestResponse().isEmpty()) {
				//选中编辑框的消息
				HttpRequestResponse httpRequestResponse = this.contextEvent.messageEditorRequestResponse().get().requestResponse();
				selectedRequestResponses.add(httpRequestResponse);
			}

			// 判断数据量是否超过100
			int splitSize = 20;
			if (selectedRequestResponses.size() > splitSize) {
				// 超过一次处理的就不允许保存到剪贴板
				if (saveOption==2){
					JOptionPane.showMessageDialog(null, "被选择的数据过多,请保存到文件中!!!");
					return;
				}

				// 划分为多个子列表进行处理
				ArrayList<ArrayList<HttpRequestResponse>> subLists = splitList(selectedRequestResponses, splitSize);
				int totalSize = subLists.size();
				for (int baseNum = 0; baseNum < totalSize; baseNum++) {
					boolean isLastList = (baseNum == totalSize - 1);
					replaceAndCopyRequestResponses(subLists.get(baseNum), saveOption, savePath, baseNum*splitSize, isLastList);
				}

			} else if (selectedRequestResponses.size() > 0){
				//直接处理
				replaceAndCopyRequestResponses(selectedRequestResponses, saveOption, savePath, 0, true);
			}
		}
	}

	/**
	 * @param selectedRequestResponses 被选择的报文列表
	 * @param saveOption 保存选项  文件|目录|剪贴板
	 * @param savePath 保存路径  文件名|目录|空
	 * @param saveBaseNum 计数基数 当保存到目录，并且被选择的报文列表超过 splitSize 时,需要这个数字作为基础计数,不然会一直在1-50循环写入
	 * @param showMsg 是不是最后一项数据,是的话就可以显示弹窗信息了
	 */
	private void replaceAndCopyRequestResponses(ArrayList<HttpRequestResponse> selectedRequestResponses, int saveOption, String savePath, int saveBaseNum, boolean showMsg) {
		//根据规则进行替换处理
		ArrayList<HttpRequestResponse> replacedRequestResponses = this.profile.replace(selectedRequestResponses, this.copyRequest, this.copyResponse);
		//根据规则进行位置提取
		String copyBuffer = this.profile.copyLocateDate(replacedRequestResponses, this.copyRequest, this.copyResponse);
		//写入内容到自定义文件或剪贴板
		if (!copyBuffer.isEmpty()){
			WriteResultToFileOrClipboard(copyBuffer, saveOption, savePath, saveBaseNum, showMsg);
		}
	}

	// 将列表划分为多个子列表
	private ArrayList<ArrayList<HttpRequestResponse>> splitList(ArrayList<HttpRequestResponse> list, int size) {
		ArrayList<ArrayList<HttpRequestResponse>> subLists = new ArrayList<>();
		for (int i = 0; i < list.size(); i += size) {
			subLists.add(new ArrayList<>(list.subList(i, Math.min(i + size, list.size()))));
		}
		return subLists;
	}
}
