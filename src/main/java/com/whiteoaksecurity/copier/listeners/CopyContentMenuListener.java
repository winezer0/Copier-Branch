package com.whiteoaksecurity.copier.listeners;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import com.whiteoaksecurity.copier.CopyProfile;

import javax.swing.*;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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

		//写入内容到自定义文件或剪贴板
		if (!copyBuffer.isEmpty()){ WriteResultToFileOrClipboard(copyBuffer);}
	}

	public static void WriteResultToFileOrClipboard(String copyBuffer) {
		// 创建一个文件选择框
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("选择文件保存路径:（取消文件保存将写入剪贴板!）");

		// 添加监听器来处理用户的选择
		int userSelection = fileChooser.showSaveDialog(null);
		if (userSelection == JFileChooser.APPROVE_OPTION) {
			File fileToSave = fileChooser.getSelectedFile();
			try {
				// 将字符串写入文件
				writeToFile(fileToSave.toPath(), copyBuffer, StandardCharsets.UTF_8);
				JOptionPane.showMessageDialog(null, "文件保存成功！");
			} catch (IOException e) {
				JOptionPane.showMessageDialog(null, "文件保存失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
			}
		} else {
			//写入内容到剪贴板
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(copyBuffer), null);
			JOptionPane.showMessageDialog(null, "写入粘贴板成功!");
		}
	}

	private static void writeToFile(Path path, String content, Charset charset) throws IOException {
		//StandardOpenOption.CREATE 在文件不存在时创建文件
		//StandardOpenOption.TRUNCATE_EXISTING 覆盖写入
		//StandardOpenOption.APPEND 追加写入
		Files.write(path, content.getBytes(charset), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
	}
}
