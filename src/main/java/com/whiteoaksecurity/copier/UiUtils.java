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
    /**
     * 保存到单个文件
     * @param copyBuffer
     */
    public static void saveToFile(String copyBuffer) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择文件保存路径:");
        int userSelection = fileChooser.showSaveDialog(null);
        //JFileChooser.APPROVE_OPTION: 用户点击了“确定”或“打开”按钮。
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try {
                Utils.writeToFileAppend(fileToSave.toPath(), copyBuffer, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(null, "文件保存成功: " + fileToSave.toPath());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "文件保存失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }

    /**
     * 保存到多个文件
     * @param copyBuffer
     */
    public static void saveToMultipleFiles(String copyBuffer) {
        // 创建一个文件夹选择框
        JFileChooser folderChooser = new JFileChooser();
        folderChooser.setDialogTitle("选择文件夹保存路径:");
        folderChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY); // 只选择文件夹
        int userSelection = folderChooser.showSaveDialog(null);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File folderToSave = folderChooser.getSelectedFile();

            try {
                // 使用正则表达式分割字符串
                java.util.List<String> parts = List.of(copyBuffer.split(CopyProfile.CONCAT));

                // 检查文件夹是否存在，不存在则创建
                if (!folderToSave.exists()) {
                    folderToSave.mkdirs();
                }

                // 保存内容到文件夹中的多个文件
                for (int i = 0; i < parts.size(); i++) {
                    String fileName = i + ".txt"; // 文件名
                    Path filePath = folderToSave.toPath().resolve(fileName);
                    String content = parts.get(i);
                    Utils.writeToFileCover(filePath, content, StandardCharsets.UTF_8);
                }
                JOptionPane.showMessageDialog(null, "文件批量保存成功: " + folderToSave.toPath());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "文件批量保存出错: " + e.getMessage());
            }
        } else {
            JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }

    /**
     * 保存到剪贴板
     * @param copyBuffer
     */
    public static void saveToClipboard(String copyBuffer) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(copyBuffer), null);
        JOptionPane.showMessageDialog(null, "写入粘贴板成功!");
    }

    /**
     *
     * @param copyBuffer
     */
    public static void WriteResultToFileOrClipboard(String copyBuffer) {
        // 弹出对话框让用户选择操作类型
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

        switch (option) {
            case 0: // 单个文件
                saveToFile(copyBuffer);
                break;
            case 1: // 多个文件
                saveToMultipleFiles(copyBuffer);
                break;
            case 2: // 保存到剪贴板
                saveToClipboard(copyBuffer);
                break;
            default: // 剪贴板
                JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }
}
