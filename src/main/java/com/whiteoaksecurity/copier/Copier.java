package com.whiteoaksecurity.copier;
import com.whiteoaksecurity.copier.components.CopyContextMenu;
import com.whiteoaksecurity.copier.models.RulesTableModel;
import com.whiteoaksecurity.copier.models.ResponseRulesTableModel;
import com.whiteoaksecurity.copier.models.RequestRulesTableModel;
import com.whiteoaksecurity.copier.listeners.ProfileComboActionListener;
import com.whiteoaksecurity.copier.listeners.AddEditProfileListener;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.annotation.JsonCreator.Mode;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import com.whiteoaksecurity.copier.listeners.AddEditRuleListener;
import com.whiteoaksecurity.copier.listeners.DeleteProfileListener;
import com.whiteoaksecurity.copier.listeners.DeleteRuleListener;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

public class Copier implements BurpExtension {
	
	JComboBox<CopyProfile> profiles;
	public final static Color FONT_COLOR = new Color(0xE58925);

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Copier");
		
		new Logger(api.logging());

		// Suite Tab
		JScrollPane suiteTab = new JScrollPane(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		
		JFrame parent = (JFrame) api.userInterface().swingUtils().suiteFrame();
		
		// Main Layout
		JPanel mainPanel = new JPanel();
		suiteTab.setViewportView(mainPanel);
		
		GroupLayout mainLayout = new GroupLayout(mainPanel);
		mainLayout.setAutoCreateGaps(true);
		mainLayout.setAutoCreateContainerGaps(true);
		mainPanel.setLayout(mainLayout);
		
		JLabel titleLabel = new JLabel("Copier Settings");			
		
        titleLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize() + 2));
        titleLabel.setForeground(FONT_COLOR);
		
		JTabbedPane tabs = new JTabbedPane();
		
		mainLayout.setHorizontalGroup(mainLayout.createParallelGroup()
			.addGroup(mainLayout.createSequentialGroup()
				.addGap(15)
				.addComponent(titleLabel)
			)
			.addComponent(tabs)
		);
		
		mainLayout.setVerticalGroup(mainLayout.createSequentialGroup()
			.addGap(15)
			.addComponent(titleLabel)
			.addGap(15)
			.addComponent(tabs)
		);
        
		// Profile Layout
        JPanel profilesPanel = new JPanel(true);
		
        GroupLayout profilesLayout = new GroupLayout(profilesPanel);
        profilesLayout.setAutoCreateGaps(true);
        profilesLayout.setAutoCreateContainerGaps(true);
		profilesPanel.setLayout(profilesLayout);
		
		JLabel profileLabel = new JLabel("Profile:");
		profileLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD, api.userInterface().currentDisplayFont().getSize()));
		
		this.profiles = new JComboBox<>();
		this.profiles.setMinimumSize(new Dimension(200, this.profiles.getPreferredSize().height));
		this.profiles.setMaximumSize(this.profiles.getPreferredSize());
		
		JButton addProfileButton = new JButton("Add");
		addProfileButton.setActionCommand("Add");
		
		JButton editProfileButton = new JButton("Edit");
		editProfileButton.setActionCommand("Edit");
		
		JButton deleteProfileButton = new JButton("Delete");
		deleteProfileButton.addActionListener(new DeleteProfileListener(parent, this.profiles));
		
		JButton duplicateProfileButton = new JButton("Duplicate");
		duplicateProfileButton.setActionCommand("Duplicate");
		
		JLabel requestRulesLabel = new JLabel("Request Copy Rules");
		requestRulesLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));
		
		RequestRulesTableModel requestRulesTableModel = new RequestRulesTableModel();
		JTable requestRulesTable = new JTable(requestRulesTableModel);
		requestRulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		
		JScrollPane requestRulesTableScrollPane = new JScrollPane(requestRulesTable);
		AddEditRuleListener requestRuleListener = new AddEditRuleListener(parent, requestRulesTable);
		
		// Add Request Rule
		JButton addRequestRuleButton = new JButton("Add");
		addRequestRuleButton.setActionCommand("Add");
		addRequestRuleButton.addActionListener(requestRuleListener);
		
		JButton editRequestRuleButton = new JButton("Edit");
		editRequestRuleButton.setActionCommand("Edit");
		editRequestRuleButton.addActionListener(requestRuleListener);
		
		JButton deleteRequestRuleButton = new JButton("Delete");
		deleteRequestRuleButton.addActionListener(new DeleteRuleListener(parent, requestRulesTable));
		
		JButton upRequestRuleButton = new JButton("Up");
		upRequestRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = requestRulesTable.getSelectedRow();
			if (selectedRow > 0) {
				
				RulesTableModel model = (RequestRulesTableModel) requestRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow - 1);
				model.fireTableDataChanged();
				requestRulesTable.repaint();
				requestRulesTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
			}
		});
		
		JButton downRequestRuleButton = new JButton("Down");
		downRequestRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = requestRulesTable.getSelectedRow();
			if (selectedRow > -1 && selectedRow < requestRulesTable.getModel().getRowCount() - 1) {
				
				RulesTableModel model = (RequestRulesTableModel) requestRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow + 1);
				model.fireTableDataChanged();
				requestRulesTable.repaint();
				requestRulesTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
			}
		});
		
		JCheckBox updateRequestContentLengthCheckBox = new JCheckBox("Update request Content-Length header after rules have been processed (in most cases this should be left disabled).", false);
		updateRequestContentLengthCheckBox.addActionListener(((ActionEvent e) -> {
			((CopyProfile) this.profiles.getSelectedItem()).setUpdateRequestContentLength(updateRequestContentLengthCheckBox.isSelected());
		}));
		
		ResponseRulesTableModel responseRulesTableModel = new ResponseRulesTableModel();
		JTable responseRulesTable = new JTable(responseRulesTableModel);
		responseRulesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
				
		JScrollPane responseRulesTableScrollPane = new JScrollPane(responseRulesTable);
		AddEditRuleListener responseRuleListener = new AddEditRuleListener(parent, responseRulesTable);
		
		JLabel responseRulesLabel = new JLabel("Response Copy Rules");
		responseRulesLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));

		JButton addResponseRuleButton = new JButton("Add");
		addResponseRuleButton.setActionCommand("Add");
		addResponseRuleButton.addActionListener(responseRuleListener);
		
		JButton editResponseRuleButton = new JButton("Edit");
		editResponseRuleButton.setActionCommand("Edit");
		editResponseRuleButton.addActionListener(responseRuleListener);
		
		JButton deleteResponseRuleButton = new JButton("Delete");
		deleteResponseRuleButton.addActionListener(new DeleteRuleListener(parent, responseRulesTable));
		
		JButton upResponseRuleButton = new JButton("Up");
		upResponseRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = responseRulesTable.getSelectedRow();
			if (selectedRow > 0) {
				
				RulesTableModel model = (ResponseRulesTableModel) responseRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow - 1);
				model.fireTableDataChanged();
				responseRulesTable.repaint();
				responseRulesTable.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
			}
		});
		
		JButton downResponseRuleButton = new JButton("Down");
		downResponseRuleButton.addActionListener((ActionEvent e) -> {
			int selectedRow = responseRulesTable.getSelectedRow();
			if (selectedRow > -1 && selectedRow < responseRulesTable.getModel().getRowCount() - 1) {
				
				RulesTableModel model = (ResponseRulesTableModel) responseRulesTable.getModel();
				Collections.swap(model.getData(), selectedRow, selectedRow + 1);
				model.fireTableDataChanged();
				responseRulesTable.repaint();
				responseRulesTable.setRowSelectionInterval(selectedRow + 1, selectedRow + 1);
			}
		});
		
		JCheckBox updateResponseContentLengthCheckBox = new JCheckBox("Update response Content-Length header after rules have been processed (in most cases this should be left disabled).", false);
		updateResponseContentLengthCheckBox.addActionListener(((ActionEvent e) -> {
			((CopyProfile) this.profiles.getSelectedItem()).setUpdateResponseContentLength(updateResponseContentLengthCheckBox.isSelected());
		}));
		
		AddEditProfileListener profileListener = new AddEditProfileListener(parent, this.profiles, requestRulesTable, responseRulesTable);
		addProfileButton.addActionListener(profileListener);
		editProfileButton.addActionListener(profileListener);
		duplicateProfileButton.addActionListener(profileListener);

		this.profiles.addActionListener(new ProfileComboActionListener(requestRulesTable, updateRequestContentLengthCheckBox, responseRulesTable, updateResponseContentLengthCheckBox));
		
		ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.registerModule(new ParameterNamesModule(Mode.PROPERTIES));
		
		JSeparator persistenceSeparator = new JSeparator();
		persistenceSeparator.setBackground(FONT_COLOR);
		
		JLabel actionLabel = new JLabel("Persistence");
		actionLabel.setFont(api.userInterface().currentDisplayFont().deriveFont(Font.BOLD));
		
		JLabel saveLabel = new JLabel("Save current profiles to Burp's internal preferences (persists between restarts).");
		JButton saveButton = new JButton("Save");
		saveButton.addActionListener((ActionEvent e) -> {
			try {
				CopyProfile[] profileArray = new CopyProfile[this.profiles.getItemCount()];
				for (int i = 0; i < this.profiles.getItemCount(); i++) {
					profileArray[i] = this.profiles.getItemAt(i);
				}
				String json = objectMapper.writeValueAsString(profileArray);
				api.persistence().preferences().setString("CopyProfiles", json);
			} catch (JsonProcessingException ex) {
				api.logging().logToError(ex.getMessage());
			}
		});
		
		JLabel restoreLabel = new JLabel("Restore profiles from Burp's internal preferences.");
		JButton restoreButton = new JButton("Restore");
		restoreButton.addActionListener((ActionEvent e) -> {
			String preferenceProfiles = api.persistence().preferences().getString("CopyProfiles");
			if (preferenceProfiles != null) {
				api.logging().logToOutput("Loading Copy Profiles from Saved Preferences.");
				try {
					List<CopyProfile> profileList = objectMapper.readValue(preferenceProfiles, new TypeReference<List<CopyProfile>>(){});
					this.profiles.removeAllItems();
					for (CopyProfile c : profileList) {
						this.profiles.addItem(c);
					}
					
					// Set Request Table Column Widths
					resizeColumnWidth(requestRulesTable);

					// Set Response Table Column Widths
					resizeColumnWidth(responseRulesTable);
				} catch (IOException ex) {
					api.logging().logToError(ex.getMessage());
				}
			}
		});
		
		JLabel resetLabel = new JLabel("Reset the profiles back to factory settings.");
		JButton resetButton = new JButton("Reset");
		resetButton.addActionListener((ActionEvent e) -> {
			this.profiles.removeAllItems();
			this.profiles.addItem(new CopyProfile("Default"));
			// Set Request Table Column Widths
			resizeColumnWidth(requestRulesTable);

			// Set Response Table Column Widths
			resizeColumnWidth(responseRulesTable);
		});
		
		JLabel exportLabel = new JLabel("Export the current profiles to a JSON file.");
		JButton exportButton = new JButton("Export");
		exportButton.addActionListener((ActionEvent e) -> {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Export Copy Profiles to File");   
 
			int userSelection = fileChooser.showSaveDialog(parent);
 
			if (userSelection == JFileChooser.APPROVE_OPTION) {
				File exportFile = fileChooser.getSelectedFile();
				try {
					BufferedWriter writer = new BufferedWriter(new FileWriter(exportFile));
					CopyProfile[] profileArray = new CopyProfile[this.profiles.getItemCount()];
					for (int i = 0; i < this.profiles.getItemCount(); i++) {
						profileArray[i] = this.profiles.getItemAt(i);
					}
					writer.write(objectMapper.writeValueAsString(profileArray));
					writer.flush();
					writer.close();
				} catch (JsonProcessingException ex) {
					api.logging().logToError(ex.getMessage());
				} catch (IOException ex) {
					api.logging().logToError(ex.getMessage());
				}
			}
		});
		
		JLabel importLabel = new JLabel("Import profiles from a JSON file.");
		JButton importButton = new JButton("Import");
		importButton.addActionListener((ActionEvent e) -> {
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Import Copy Profiles from File");
			
			int userSelection = fileChooser.showOpenDialog(parent);
			
			if (userSelection == JFileChooser.APPROVE_OPTION) {
				File importFile = fileChooser.getSelectedFile();
				try {
					StringBuilder sb = new StringBuilder();
					BufferedReader br = new BufferedReader(new FileReader(importFile));
					String line;
					while ((line = br.readLine()) != null) {
						sb.append(line).append("\n");
					}
					br.close();
					
					List<CopyProfile> profileList = objectMapper.readValue(sb.toString(), new TypeReference<List<CopyProfile>>(){});					
					this.profiles.removeAllItems();

					for (CopyProfile c : profileList) {
						this.profiles.addItem(c);
					}
					
					// Set Request Table Column Widths
					resizeColumnWidth(requestRulesTable);

					// Set Response Table Column Widths
					resizeColumnWidth(responseRulesTable);
				}
				catch (IOException ex) {
					api.logging().logToError(ex.getMessage());
				}
				catch (Exception ex) {
					for (StackTraceElement a : ex.getStackTrace())
					{
						api.logging().logToError(a.toString());
					}
				}
			}
		});
		
		JSeparator authorSeparator = new JSeparator();
		authorSeparator.setBackground(FONT_COLOR);
		JLabel authorLabel = new JLabel("Copier was created by Tib3rius & White Oak Security.");
		
		profilesLayout.setHorizontalGroup(profilesLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(profilesLayout.createParallelGroup()
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(profileLabel)
					.addComponent(this.profiles)
					.addComponent(addProfileButton)
					.addComponent(editProfileButton)
					.addComponent(duplicateProfileButton)
					.addComponent(deleteProfileButton)
				)
				.addComponent(requestRulesLabel)
				.addGroup(profilesLayout.createSequentialGroup()
					.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
						.addComponent(addRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(editRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(deleteRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(upRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(downRequestRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					)
					.addComponent(requestRulesTableScrollPane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
				)
				.addComponent(updateRequestContentLengthCheckBox)
				.addComponent(responseRulesLabel)
				.addGroup(profilesLayout.createSequentialGroup()
					.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
						.addComponent(addResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(editResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(deleteResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(upResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(downResponseRuleButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					)
					.addComponent(responseRulesTableScrollPane, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE)
				)
				.addComponent(updateResponseContentLengthCheckBox)
				.addComponent(persistenceSeparator)
				.addComponent(actionLabel)
				.addGroup(profilesLayout.createSequentialGroup()
					.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
						.addComponent(saveButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(restoreButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(resetButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(exportButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(importButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					)
					.addGroup(profilesLayout.createParallelGroup()
						.addComponent(saveLabel)
						.addComponent(restoreLabel)
						.addComponent(resetLabel)
						.addComponent(exportLabel)
						.addComponent(importLabel)
					)
				)
				.addComponent(authorSeparator)
				.addComponent(authorLabel)
			)
			.addGap(15)
		);
		
		profilesLayout.setVerticalGroup(profilesLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
				.addComponent(profileLabel)
				.addComponent(this.profiles)
				.addComponent(addProfileButton)
				.addComponent(editProfileButton)
				.addComponent(duplicateProfileButton)
				.addComponent(deleteProfileButton)
			)
			.addGap(15)
			.addComponent(requestRulesLabel)
			.addGap(10)
			.addGroup(profilesLayout.createParallelGroup()
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(addRequestRuleButton)
					.addComponent(editRequestRuleButton)
					.addComponent(deleteRequestRuleButton)
					.addComponent(upRequestRuleButton)
					.addComponent(downRequestRuleButton)
				)
				.addComponent(requestRulesTableScrollPane, 150, 150, 150)
			)
			.addGap(15)
			.addComponent(updateRequestContentLengthCheckBox)
			.addGap(15)
			.addComponent(responseRulesLabel)
			.addGap(10)
			.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(addResponseRuleButton)
					.addComponent(editResponseRuleButton)
					.addComponent(deleteResponseRuleButton)
					.addComponent(upResponseRuleButton)
					.addComponent(downResponseRuleButton)
				)
				.addComponent(responseRulesTableScrollPane, 150, 150, 150)
			)
			.addGap(15)
			.addComponent(updateResponseContentLengthCheckBox)
			.addGap(15)
			.addComponent(persistenceSeparator, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
			.addGap(10)
			.addComponent(actionLabel)
			.addGap(10)
			.addGroup(profilesLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(saveButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(restoreButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(resetButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(exportButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(importButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				)
				.addGroup(profilesLayout.createSequentialGroup()
					.addComponent(saveLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(restoreLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(resetLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(exportLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(importLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				)
			)
			.addGap(15)
			.addComponent(authorSeparator, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
			.addGap(10)
			.addComponent(authorLabel)
			.addContainerGap()
		);
		
		// Help Layout
		JPanel helpPanel = new JPanel();
		GroupLayout helpLayout = new GroupLayout(helpPanel);
		helpLayout.setAutoCreateGaps(true);
		helpLayout.setAutoCreateContainerGaps(true);
		helpPanel.setLayout(helpLayout);
		
		JTextArea helpDesc = new JTextArea("""
            Copier allows users to create different profiles comprised of match & replace rules for both requests and responses. These profiles can then be applied when copying a request / response, saving reporting time.
            
            For example, a rule could be created to truncate Bearer tokens in requests, remove "Sec-" headers, or even automatically redact sensitive information.
            
            To add a new profile, click the "Add" button next to the profile drop-down menu and enter a unique profile name. When a profile is selected, its name can be edited by clicking the "Edit" button. Similarly, a selected profile can be deleted using the "Delete" button. A profile and all its rules can be duplicated using the "Duplicate" button to save time creating similar rules.
            
             
        """);
		
		helpDesc.setEditable(false);
		helpDesc.setBorder(new LineBorder(Color.RED, 0));
		
		helpLayout.setHorizontalGroup(helpLayout.createSequentialGroup()
			.addGap(15)
			.addGroup(helpLayout.createParallelGroup()
				.addComponent(helpDesc)
			)
			.addGap(15)
		);
		
		helpLayout.setVerticalGroup(helpLayout.createSequentialGroup()
			.addGap(15)
			.addComponent(helpDesc)
			.addContainerGap()
		);
		
		tabs.addTab("Profiles", profilesPanel);
		//tabs.addTab("Help", helpPanel);
		
		// Load Profiles From Saved Preferences
		String preferenceProfiles = api.persistence().preferences().getString("CopyProfiles");
		if (preferenceProfiles != null) {
			api.logging().logToOutput("Loading Copy Profiles from Saved Preferences.");
			try {
				List<CopyProfile> profileList = objectMapper.readValue(preferenceProfiles, new TypeReference<List<CopyProfile>>(){});
				for (CopyProfile c : profileList) {
					this.profiles.addItem(c);
				}
			} catch (IOException ex) {
				api.logging().logToError(ex.getMessage());
			}
		}
		
		// If there are no Copy Profiles, create a Default one.
		if (this.profiles.getItemCount() == 0) {
			this.profiles.addItem(new CopyProfile("Default"));
		}
		
		// Load Rules from the first Copy Profile.
		this.profiles.setSelectedIndex(0);
		requestRulesTable.setModel(((CopyProfile) this.profiles.getItemAt(0)).getRequestRulesTableModel());
		responseRulesTable.setModel(((CopyProfile) this.profiles.getItemAt(0)).getResponseRulesTableModel());
		
		// Set Request Table Column Widths
		resizeColumnWidth(requestRulesTable);
		
		// Set Response Table Column Widths
		resizeColumnWidth(responseRulesTable);
		
		api.userInterface().applyThemeToComponent(suiteTab);
		api.userInterface().registerSuiteTab("Copier", suiteTab);
		api.userInterface().registerContextMenuItemsProvider(new CopyContextMenu(api, this.profiles));

    }
	
	public static void resizeColumnWidth(JTable table) {
		TableColumnModel columnModel = table.getColumnModel();
		// EnabledBase64 Column
		columnModel.getColumn(0).setPreferredWidth(100);
		columnModel.getColumn(0).setResizable(false);

		// Case Sensitive Column
		columnModel.getColumn(1).setPreferredWidth(100);
		columnModel.getColumn(1).setResizable(false);


		// Location Column
		columnModel.getColumn(2).setPreferredWidth(150);



		// Match Column
		columnModel.getColumn(3).setPreferredWidth(150);
		
		// Replace Column
		columnModel.getColumn(4).setPreferredWidth(150);
		
		// Type Column
		columnModel.getColumn(5).setPreferredWidth(columnModel.getColumn(0).getPreferredWidth());
		columnModel.getColumn(5).setResizable(false);
		DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
		centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
		columnModel.getColumn(5).setCellRenderer(centerRenderer);

		
		// Comment Column
		columnModel.getColumn(6).setPreferredWidth(350);
	}
}