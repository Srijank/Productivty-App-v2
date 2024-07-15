function minimumDate(type,datetoshow){
    var date = new Date();
    var month = date.getMonth()+1;
    var dates = date.getDate();
    var day = date.getDay();
    var year = date.getFullYear();
   
    
if (type==='max'){
    var daysRemaining = 7- day;
    dates = dates+daysRemaining;
   if(dates>28){

   if(getnewMonth(month,year) ===28){                
    dates= dates-28;
   }
   else if(getnewMonth(month,year) ===29){
    dates= dates-29;
   }
   else if(getnewMonth(month,year) ===30){
    dates= dates-29;
   }
   if(month===12){
    month=1;
    year= year+1;
   }
   month=month+1;

}

}
else if (type==='togetdate'){
    var date = new Date(datetoshow);
    var month = date.getMonth()+1;
    var dates = date.getDate();
    var day = date.getDay();
    var year = date.getFullYear();
}
if (month<10){
    month = '0' + month.toString();
}
if (dates<10){
    dates = '0' + dates.toString();
}
return (`${year}-${month}-${dates}`);
}
function getnewMonth(month,year){
if (month===1 || month==3 || month===5 || month===7 || month===8 || month===10 || month===12){
return 31;
}
if (month==='04' || month=='06' || month==='09' || month==='11'){
return 30;
}
if(month==='02'){
if((year%4===0 && year%100!=0 )||year%400){
return 29;
}
else{
    return 28;
}
}
}


document.addEventListener('DOMContentLoaded', function() {
var dateInput = document.getElementsByClassName('deadline');
//console.log(dateInput[1]);
dateInput[0].setAttribute('min', minimumDate('min',null));
dateInput[1].setAttribute('min', minimumDate('min',null));
dateInput[0].setAttribute('max', minimumDate('max',null));
dateInput[1].setAttribute('max', minimumDate('max',null));

});

const add_icon = Array.from(document.getElementsByClassName("add_icon"));
add_icon.forEach(function(add_icon,index){
   add_icon.addEventListener("click", ()=>{
       const popup= document.getElementsByClassName("pop_up")[0];
       popup.style.visibility= "visible";
       document.querySelectorAll('.toblurcontent').forEach((element) => { 
        if (!element.classList.contains('pop_up')) {
            element.classList.add('blurred');
        }
    });
       
});

});

const close_icon = Array.from(document.getElementsByClassName("btn-close"));
close_icon.forEach(function(close_icon,index){
    close_icon.addEventListener("click", ()=>{
        const popup= document.getElementsByClassName("pop_up")[0];
        const edit_popup= document.getElementsByClassName("edit_pop_up")[0];
        popup.style.visibility= "hidden";
        edit_popup.style.visibility= "hidden";
        document.querySelectorAll('.toblurcontent').forEach((element) => {
            if (!element.classList.contains('pop_up') || !element.classList.contains('edit_pop_up')) {
                element.classList.remove('blurred');
            }
});
});
    });

const edit_icon = Array.from(document.getElementsByClassName("edit_icon"));
edit_icon.forEach(function(editicon,index){
     editicon.addEventListener("click", ()=>{
        const popup= document.getElementsByClassName("edit_pop_up")[0];
        popup.style.visibility= "visible";
        document.querySelectorAll('.toblurcontent').forEach((element) => { 
            if (!element.classList.contains('edit_pop_up')) {
                element.classList.add('blurred');
            }
        });
});
    
    });

document.addEventListener("click",(event)=>{
    const classRecieved = (event.target.className).split(" ")[0];
    if(classRecieved==='edit_icon'){
        const classRequired =(event.target.className).split(" ")[1];
     const editContent =document.getElementsByClassName(classRequired);
      const toedit = document.getElementsByClassName("edit_value");
      console.log(editContent[7].innerHTML);
      console.log(editContent[3].innerHTML);
      console.log(editContent[4].innerHTML);
      //Task name
       toedit[0].setAttribute('value',editContent[1].innerHTML.trim());
       //Description
       toedit[1].setAttribute('value',editContent[3].innerHTML.trim());
       //Imapct
       toedit[2].setAttribute('value',editContent[2].innerHTML.trim());
       //taskid
       toedit[3].setAttribute('value',editContent[8].innerHTML.trim());
       //status
       toedit[4].setAttribute('value',editContent[4].innerHTML.trim());
       toedit[4].innerHTML=editContent[4].innerHTML.trim();
       //priority
       toedit[5].setAttribute('value',editContent[5].innerHTML.trim());
       toedit[5].innerHTML=editContent[5].innerHTML.trim();
       //deadline
       
        const dateStr = editContent[6].innerHTML.trim();
        const [day, month, year] = dateStr.split('/');
       const dateObject = new Date(`${year}-${month}-${day}`);
       const dates = minimumDate("togetdate",dateObject);
       toedit[6].value = dates;
       //reward
       toedit[7].setAttribute('value',editContent[9].innerHTML.trim());

}
});

const selectedItems= [];
const taskid =[];
const checkboxesClicked = Array.from(document.getElementsByClassName("tick"));
const add_image = Array.from(document.getElementsByClassName('add_icon'));
const edit_image =  Array.from(document.getElementsByClassName('edit_icon'));
// console.log(checkboxesClicked);
checkboxesClicked.forEach(function(checkbox){
     checkbox.addEventListener("click", ()=>{
        console.log(checkbox.classList[1]);
        const secondClass= checkbox.classList[1];
        console.log(secondClass);
        const detail = document.getElementsByClassName(secondClass)[8];
        let index = selectedItems.indexOf(secondClass)
        if(index!==-1){
        selectedItems.splice(index,1);
        taskid.splice(index,1);
        }
        else{
            selectedItems.push(secondClass);
            taskid.push(detail.innerHTML)
        }
        if (selectedItems.length>0){
            add_image.forEach(function (add){
                add.classList.add('disabled');
            });
            edit_image.forEach(function (edit){
                edit.classList.add('disabled');
            });
        }
        else if (selectedItems.length===0) {
            add_image.forEach(function (add){
                add.classList.remove('disabled');
            });
            edit_image.forEach(function (edit){
                edit.classList.remove('disabled');
            });
        }
          
        });
    });
        document.getElementsByClassName('delete-icon')[0].addEventListener("click",()=>{
           if ( confirm("Are you sure you want to delete the tasks ? ")){
            // Send the task ID to the server using fetch API
            fetch('/delete-task', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ taskId: taskid })
            })
            .then(response => {
              if (response.ok) {
                window.location.reload();
                console.log('Task deleted successfully');
              } else {
                console.error('Failed to delete the task');
              }
            })
            .catch(error => {
              console.error('Error:', error);
            });
        }
    
    });   
 const descriptionLogic = Array.from(document.getElementsByClassName('description'));
 //console.log(descriptionLogic);
 descriptionLogic.forEach(function(value){
    if(value.innerHTML.trim().length===0){
        value.innerHTML='NA';
        value.classList.add('na-font');
      
    }
 });

 document.addEventListener('DOMContentLoaded', function () {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl)
    })
  });

const statusoftask = Array.from(document.getElementsByClassName('statusoftask'));
statusoftask.forEach(function(status){
    console.log(status.innerHTML.trim());
    if(status.innerHTML.trim()==='To do'){
        status.classList.add('green');
    }
    else if(status.innerHTML.trim()==='In progress'){
        status.classList.add('orange');
    }
    else if(status.innerHTML.trim()==='In review'){
        status.classList.add('green');
    }
});

const priorityoftask = Array.from(document.getElementsByClassName('priorityoftask'));
priorityoftask.forEach(function(priority){
    
    if(priority.innerHTML.trim()==='P1'){
        priority.classList.add('red');
    }
    else if(priority.innerHTML.trim()==='P2'){
        priority.classList.add('orange');
    }
    else if(priority.innerHTML.trim()==='P3'){
        priority.classList.add('grey');
    }
    else if(priority.innerHTML.trim()==='P4'){
        priority.classList.add('green');
    }
});
document.getElementById('calendar').addEventListener('click', function() {
    const calendarInput = document.getElementById('calendartoshow');
    calendarInput.style.display = 'block';
    calendarInput.focus();
  });
document.getElementById('calendartoshow').addEventListener('blur', function() {
    setTimeout(() => {
      this.style.display = 'none';
    }, 200); // Slight delay to ensure the date is selected before hiding
  });



// console.log(taskList);
    // var text =(event.target.className).split(" ")[1]; 
    // var item1 =document.getElementsByClassName(text)[1];
    // var item2 = document.getElementsByClassName(text)[2];
    // var item3= document.getElementsByClassName(text)[3];
    // item1.classList.toggle('completed');
    // item2.classList.toggle('completed');
    // item3.classList.toggle('completed');
   


