from javax.swing import JTable;
from javax.swing.table import AbstractTableModel;
from java.awt.event import MouseListener
import traceback
import Utils

class JobTable(JTable):
    def __init__(self, extender):
        self._extender = extender

        model = JobTableModel(extender)
        self.setModel(model)

        self.setAutoResizeMode(JTable.AUTO_RESIZE_NEXT_COLUMN); 
        colModel = self.getColumnModel()
        colModel.getColumn(0).setMaxWidth(50)    
        colModel.getColumn(1).setMaxWidth(100)
        colModel.getColumn(3).setMaxWidth(50)    
        colModel.getColumn(4).setMaxWidth(50)

        self.addMouseListener(JobTableMouseListener(extender))
        self.setAutoCreateRowSorter(True)

    def updateTable(self):
        self.getModel().fireTableDataChanged()

class JobTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        try:
            return self._extender.getSelectedJob().getFuzLength()
        except:
            return 0

    def getColumnCount(self):
        return 6+len(Utils.WORDS_TO_SEARCH_IN_RESPONSE)

    def getColumnName(self, columnIndex):
        lastIndexBeforeGreps = 4
        if columnIndex == 0:
            return "Id"
        if columnIndex == 1:
            return "parameter"
        if columnIndex == 2:
            return "payload"
        if columnIndex == 3:
            return "status"
        if columnIndex == lastIndexBeforeGreps:
            return "length"
        if columnIndex >= lastIndexBeforeGreps+1 and columnIndex <= lastIndexBeforeGreps + len(Utils.WORDS_TO_SEARCH_IN_RESPONSE):
            return "Grep: "+Utils.WORDS_TO_SEARCH_IN_RESPONSE[columnIndex-lastIndexBeforeGreps-1]
        if columnIndex == lastIndexBeforeGreps+len(Utils.WORDS_TO_SEARCH_IN_RESPONSE)+1:
            return "time"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        lastIndexBeforeGreps = 4
        try:
            fuzEntry = self._extender.getSelectedJob().getFuzByRow(rowIndex)
            if columnIndex == 0:
                return fuzEntry["id"]
            if columnIndex == 1:
                try:
                    return fuzEntry["parameter"].getName()
                except KeyError:
                    return "NO_CHANGE"
            if columnIndex == 2:
                try:
                    return fuzEntry["parameter"].getValue()
                except KeyError:
                    return "NO_CHANGE"
            if columnIndex == 3:
                try:
                    return fuzEntry["reqResp"].getStatusCode()
                except:
                    return "..."
            if columnIndex == 4:
                try:
                    return len(fuzEntry["reqResp"].getResponse())
                except:
                    return "..."
            if columnIndex >= lastIndexBeforeGreps+1 and columnIndex <= lastIndexBeforeGreps + len(Utils.WORDS_TO_SEARCH_IN_RESPONSE):
                greped = Utils.WORDS_TO_SEARCH_IN_RESPONSE[columnIndex-lastIndexBeforeGreps-1]
                try:
                    return fuzEntry["grep"][greped]
                except:
                    return "False"
            if columnIndex == lastIndexBeforeGreps+len(Utils.WORDS_TO_SEARCH_IN_RESPONSE)+1:
                try:
                    headers = fuzEntry["analyzedResp"].getHeaders()
                    for header in headers:
                        if header.startswith("Date: "):
                            return header[6:-1] 
                except KeyError:
                    pass
                finally:
                    return "n/a"
            return ""
        except Exception as e:
            self._extender.log(e, True)
            traceback.print_exc()
            return "Exception"

class JobTableMouseListener(MouseListener):
    def __init__(self, extender):
        self._extender = extender
    
    def getClickedIndex(self, event):
        """Returns the value of the first column of the table row that was
        clicked. This is not the same as the row index because the table
        can be sorted."""
        # get the event source, the table in this case.
        tbl = event.getSource()
        # get the clicked row
        row = tbl.getSelectedRow()
        # get the first value of clicked row
        return tbl.getValueAt(row, 0)
        # return event.getSource.getValueAt(event.getSource().getSelectedRow(), 0)

    def getClickedRow(self, event):
        """Returns the complete clicked row."""
        tbl = event.getSource()
        mdl = tbl.getModel()
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        assert isinstance(mdl, JobTableModel)
        return self._extender.getSelectedJob().getFuzByRow(row)

    # event.getClickCount() returns the number of clicks.
    def mouseClicked(self, event):
        try:
            if event.getClickCount() == 2:
                self._extender.openRequestResponsePanel(self.getClickedRow(event))
                return
        except Exception as e:
            self._extender.log(e, True)

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass    
    
    def mousePressed(self, event):
        # print "mouse pressed", event.getClickCount()
        pass

    def mouseReleased(self, event):
        # print "mouse released", event.getClickCount()
        pass