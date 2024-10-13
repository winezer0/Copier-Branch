package com.whiteoaksecurity.copier.listeners;

import com.whiteoaksecurity.copier.CopyProfile;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class DeleteProfileListener implements ActionListener {
	private JFrame parent;
	private JComboBox<CopyProfile> profileCombo;
	private boolean isDialogOpen;
	
	public DeleteProfileListener(JFrame parent, JComboBox<CopyProfile> profileCombo) {
		this.parent = parent;
		this.profileCombo = profileCombo;
		this.isDialogOpen = false;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		if (!this.isDialogOpen) {
			this.isDialogOpen = true;
			
			if (this.profileCombo.getItemCount() == 1) {
				JOptionPane.showMessageDialog(this.parent, "You can't delete the last profile!", "Error!", JOptionPane.ERROR_MESSAGE);
				this.isDialogOpen = false;
			} else {
				String[] options = {"No", "Yes"};
				CopyProfile selectedItem = (CopyProfile) this.profileCombo.getSelectedItem();
				int decision = JOptionPane.showOptionDialog(
					this.parent,
					"Are you sure you want to delete the \"" + selectedItem.getName() + "\" profile?",
					"Delete Profile?",
					JOptionPane.YES_NO_OPTION,
					JOptionPane.WARNING_MESSAGE,
					null,
					options,
					options[1]
				);

				if (decision ==  1) {
					int oldItemCount = profileCombo.getItemCount();
					this.profileCombo.removeItem(selectedItem);
					int newItemCount = profileCombo.getItemCount();
					CopyProfile newSelectedItem = (CopyProfile) this.profileCombo.getSelectedItem();
					System.out.println(String.format("移除 Profile Item: %s -> %s || ItemCount: %s -> %s",
							selectedItem.getName(), newSelectedItem.getName(), oldItemCount, newItemCount));

/*
					// 获取移除后的第一个元素 默认是向前自动移动一个
					int itemCount = this.profileCombo.getItemCount();
					if (itemCount > 0) {
						// 设置第一个元素为选中项
						this.profileCombo.setSelectedIndex(0);
						selectedItem = (CopyProfile) this.profileCombo.getSelectedItem();
						System.out.println(String.format("当前选择 selectedItem: %s -> Count: %s", selectedItem.getName(),profileCombo.getItemCount()));
					} else {
						// 如果没有项目了，可能需要处理这种情况，例如显示提示信息给用户
						System.out.println("No items left in the combo box.");
					}
*/
				}
				
				this.isDialogOpen = false;
			}
		}
	}
}
