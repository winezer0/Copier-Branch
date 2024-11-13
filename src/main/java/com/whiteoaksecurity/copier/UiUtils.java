package com.whiteoaksecurity.copier;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

public class UiUtils {

    public static final int saveToOneFile = 0;
    public static final int SaveToMultipleFiles = 1;
    public static final int SaveToClipboard = 2;

    /**
     * 保存到单个文件
     * @param copyBuffer
     */
    public static void saveToFile(String copyBuffer, String fileToSavePath, boolean showMsgDialog) {
        try {
            File fileToSave = new File(fileToSavePath);
            Utils.writeToFileAppend(fileToSave.toPath(), copyBuffer, StandardCharsets.UTF_8);

            if (showMsgDialog) JOptionPane.showMessageDialog(null, "文件保存成功: " + fileToSave.toPath());
        } catch (IOException e) {
            if (showMsgDialog) JOptionPane.showMessageDialog(null, "文件保存失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 保存到多个文件
     * @param copyBuffer
     */
    public static void saveToMultipleFiles(String copyBuffer, String folderToSavePath, int saveBaseNum, boolean showMsgDialog) {
        try {
            File folderToSave = new File(folderToSavePath);
            // 使用正则表达式分割字符串
            java.util.List<String> parts = List.of(copyBuffer.split(CopyProfile.CONCAT));
            // 检查文件夹是否存在，不存在则创建
            if (!folderToSave.exists()) {
                folderToSave.mkdirs();
            }

            // 保存内容到文件夹中的多个文件
            for (int i = 0; i < parts.size(); i++) {
                String fileName = (saveBaseNum + i) + ".txt"; // 文件名
                Path filePath = folderToSave.toPath().resolve(fileName);
                String content = parts.get(i);
                Utils.writeToFileCover(filePath, content, StandardCharsets.UTF_8);
            }
            if (showMsgDialog) JOptionPane.showMessageDialog(null, "文件批量保存成功: " + folderToSave.toPath());
        } catch (IOException e) {
            if (showMsgDialog) JOptionPane.showMessageDialog(null, "文件批量保存出错: " + e.getMessage());
        }
    }

    /**
     * 保存到剪贴板
     * @param copyBuffer
     */
    public static void saveToClipboard(String copyBuffer, boolean showMsgDialog) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(copyBuffer), null);
        if (showMsgDialog) JOptionPane.showMessageDialog(null, "写入粘贴板成功!");
    }

    /**
     * 弹出对话框让用户选择操作类型
     */
    public static int getSaveOption() {
        int option = JOptionPane.showOptionDialog(
                null,
                "请选择您想要的操作：",
                "文件保存选项",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                new Object[]{"保存到单个文件", "保存到多个文件", "保存到剪贴板"},
                "保存到单个文件"
        );
        return option;
    }


    public static String getFileSavePath(String fileOrDirToSavePath) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择文件保存路径:");
        int userSelection = fileChooser.showSaveDialog(null);
        //JFileChooser.APPROVE_OPTION: 用户点击了“确定”或“打开”按钮。
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            fileOrDirToSavePath = fileToSave.getAbsolutePath(); //此抽象路径名的绝对路径名的字符串
        } else {
            JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
        return fileOrDirToSavePath;
    }


    public static String getDirToSavePath(String fileOrDirToSavePath) {
        // 创建一个文件夹选择框
        JFileChooser folderChooser = new JFileChooser();
        folderChooser.setDialogTitle("选择文件夹保存路径:");
        folderChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY); // 只选择文件夹
        int userSelection = folderChooser.showSaveDialog(null);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File folderToSave = folderChooser.getSelectedFile();
            fileOrDirToSavePath = folderToSave.getAbsolutePath();
        } else {
            JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
        return fileOrDirToSavePath;
    }


    /**
     * 根据用户选项弹框,获取保存文件路径
     * @param saveOption
     */
    public static String getFileOrDirToSavePath(int saveOption) {
        String fileOrDirToSavePath = null;

        switch (saveOption) {
            case saveToOneFile: // 单个文件
                fileOrDirToSavePath = getFileSavePath(fileOrDirToSavePath);
                break;
            case SaveToMultipleFiles: // 多个文件
                fileOrDirToSavePath = getDirToSavePath(fileOrDirToSavePath);
                break;
            case SaveToClipboard: // 保存到剪贴板
                fileOrDirToSavePath = "";
                break;
            default: // 剪贴板
                JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
        return fileOrDirToSavePath;
    }

    /**
     * 根据用户选项和报文文件路径写入提取结果
     * @param saveOption
     */
    public static void WriteResultToFileOrClipboard(String copyBuffer, int saveOption, String fileOrDirToSavePath, int baseNum, boolean showMsg) {

        switch (saveOption) {
            case saveToOneFile: // 单个文件
                saveToFile(copyBuffer, fileOrDirToSavePath, showMsg);
                break;
            case SaveToMultipleFiles: // 多个文件
                saveToMultipleFiles(copyBuffer, fileOrDirToSavePath, baseNum, showMsg);
                break;
            case SaveToClipboard: // 保存到剪贴板
                saveToClipboard(copyBuffer, showMsg);
                break;
            default: // 不保存
                JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }

}
