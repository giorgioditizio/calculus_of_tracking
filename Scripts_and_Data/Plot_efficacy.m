%plot the effectiveness of different tracking blocking protection for the
%Top X alexa domains
clear all
close all
%read CVS file containing Knows and Access for different Top alexa and
%mitigations

Table_access = readtable('CSV/Access_graph_2019.csv','ReadVariableNames',true);
Table_knows = readtable('CSV/Knows_graph_2019.csv','ReadVariableNames',true);

mitigations = ["","ELEP_19","D_19","A_19",'PB'];
top = ["5","10","50","100"];

matrix_access = [];
matrix_knows = [];

for i=1:length(mitigations)
    tmp_snapshot = mitigations(i);
    %this generate a sequence of 0 and 1 in the position where we have the
    %same snapshot
    logic_estraction_knows = Table_knows.('Snapshot')==tmp_snapshot;
    logic_estraction_access = Table_access.('Snapshot')==tmp_snapshot;
    %use this to extract element from the other column of Table_Knows and
    %Access
    %then convert to string and then to cell so that we can add it to the
    %cellround((matrix_access./matrix_access(1,:))*100);
    
    tmp_line_knows = Table_knows.('Value')(logic_estraction_knows);
    tmp_line_access = Table_access.('Value')(logic_estraction_access);
    
    %add the type of mitigation in each line
    matrix_access = [matrix_access; tmp_line_access'];
    matrix_knows = [matrix_knows; tmp_line_knows'];
    
end
%now compute the percentage of access and knows based on the maximum value
%we have (that is from the snapshot without any mitigation)

matrix_access = round((matrix_access./matrix_access(1,:))*100); 
%drop the first line because we do not print it
matrix_access(1,:) = [];
matrix_knows = round((matrix_knows./matrix_knows(1,:))*100);
%drop the first line because we do not print it
matrix_knows(1,:) = [];

%plot figure Allowed Tracker-Allowed Connections
figure
hold on
%iterate over the mitigations (but ignore the first one i.e. no mitigs)
markers = ['o','*','^','+','p','x','s'];
colors = ['r','g','b','c','m','b','k'];
line_style = ["-","--",":","-.","-",":","-."];
labels = ["EasyList&EasyPrivacy","Disconnect","Adblockplus","Privacy Badger"];
for i=1:length(labels)
    plot(matrix_access(i,:),matrix_knows(i,:),'MarkerFaceColor',colors(i),'Color',colors(i),'Marker',markers(i),'LineWidth',1,'DisplayName',labels(i),'LineStyle',line_style(i));
    text(matrix_access(i,:)-2.0,matrix_knows(i,:)+1.0,top,'fontsize',6);
end
line([0:20:100],[0:20:100],'Color',[0.5 0.5 0.5],'LineStyle','--','LineWidth',1,'HandleVisibility','off');
text(61,60,'\leftarrow 1-for-1','fontsize',8)
line([0:20:100],[0:10:50],'Color',[0.5 0.5 0.5],'LineStyle','-.','LineWidth',1,'HandleVisibility','off');
text(80,39,'\leftarrow 1-for-2','fontsize',8)
legend
xlabel('Fraction of Allowed Connections')
ylabel('Fraction of Potential Trackers')
ylim([0 100])
xlim([0 100])
xticks((0:20:100))
yticks((0:20:100))
xticklabels({'0%','20%','40%','60%','80%','100%'})
yticklabels({'0%','20%','40%','60%','80%','100%'})

%% 2016 VERSION

Table_access = readtable('CSV/Access_graph_2016.csv','ReadVariableNames',true);
Table_knows = readtable('CSV/Knows_graph_2016.csv','ReadVariableNames',true);

mitigations = ["","G","D","A"];
top = ["5","10","50","100"];

matrix_access = [];
matrix_knows = [];

for i=1:length(mitigations)
    tmp_snapshot = mitigations(i);
    %this generate a sequence of 0 and 1 in the position where we have the
    %same snapshot
    logic_estraction_knows = Table_knows.('Snapshot')==tmp_snapshot;
    logic_estraction_access = Table_access.('Snapshot')==tmp_snapshot;
    %use this to extract element from the other column of Table_Knows and
    %Access
    %then convert to string and then to cell so that we can add it to the
    %cellround((matrix_access./matrix_access(1,:))*100);
    
    tmp_line_knows = Table_knows.('Value')(logic_estraction_knows);
    tmp_line_access = Table_access.('Value')(logic_estraction_access);
    
    %add the type of mitigation in each line
    matrix_access = [matrix_access; tmp_line_access'];
    matrix_knows = [matrix_knows; tmp_line_knows'];
    
end
%now compute the percentage of access and knows based on the maximum value
%we have (that is from the snapshot without any mitigation)

matrix_access = round((matrix_access./matrix_access(1,:))*100); 
%drop the first line because we do not print it
matrix_access(1,:) = [];
matrix_knows = round((matrix_knows./matrix_knows(1,:))*100);
%drop the first line because we do not print it
matrix_knows(1,:) = [];

%plot figure Allowed Tracker-Allowed Connections
figure
hold on
%iterate over the mitigations (but ignore the first one i.e. no mitigs)
markers = ['o','*','^','+','p','x','s'];
colors = ['r','g','b','c','m','b','k'];
line_style = ["-","--",":","-.","-",":","-."];
labels = ["Ghostery","Disconnect","Adblockplus"];
for i=1:length(labels)
    plot(matrix_access(i,:),matrix_knows(i,:),'MarkerFaceColor',colors(i),'Color',colors(i),'Marker',markers(i),'LineWidth',1,'DisplayName',labels(i),'LineStyle',line_style(i));
    text(matrix_access(i,:)-2.0,matrix_knows(i,:)+1.0,top,'fontsize',6);
end
line([0:20:100],[0:20:100],'Color',[0.5 0.5 0.5],'LineStyle','--','LineWidth',1,'HandleVisibility','off');
text(61,60,'\leftarrow 1-for-1','fontsize',8)
line([0:20:100],[0:10:50],'Color',[0.5 0.5 0.5],'LineStyle','-.','LineWidth',1,'HandleVisibility','off');
text(80,39,'\leftarrow 1-for-2','fontsize',8)
legend
xlabel('Fraction of Allowed Connections')
ylabel('Fraction of Potential Trackers')
ylim([0 100])
xlim([0 100])
xticks((0:20:100))
yticks((0:20:100))
xticklabels({'0%','20%','40%','60%','80%','100%'})
yticklabels({'0%','20%','40%','60%','80%','100%'})