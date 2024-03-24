document.addEventListener('DOMContentLoaded', function () {
    var searchInput = document.querySelector('.search_bar');
    var searchForm = document.querySelector('form');

    searchForm.addEventListener('submit', function (event) {
        event.preventDefault();
        searchInput.value = '';
    });
    let left_Btn = document.querySelector("#one");
    let play_Btn = document.querySelector("#two");
    let right_Btn = document.querySelector("#three");
    let pause_Btn = document.querySelector("#four");
    let audio_Btn = document.querySelector("Audio");
    let album_Image = document.querySelector(".album_img");

    play_Btn.addEventListener('click', () => {
        audio_Btn.play();
        play_Btn.style.display = "none";
        pause_Btn.style.display = "flex"
        album_Image.classList.add('rotation');
    })

    pause_Btn.addEventListener('click', () => {
        audio_Btn.pause();
        pause_Btn.style.display = 'none';
        play_Btn.style.display = 'flex';
        album_Image.classList.remove('rotation');
    })

    document.addEventListener("DOMContentLoaded", function () {
        let artistNameElement = document.querySelector(".artist_name");
        let songNameElement = document.querySelector(".song_name");
        let marqueeElement = document.querySelector(".footer_div marquee");

        marqueeElement.textContent = songNameElement.textContent + ' by ' + artistNameElement.textContent;

    });


    let lastClickTime = 0;

    left_Btn.addEventListener('click', () => {
        let currentTime = new Date().getTime();
        if (currentTime - lastClickTime < 300) {// Check if double click
            audio_Btn.pause();
            audio_Btn.currentTime = 0;
        } else {
            audio_Btn.play();
        }
        lastClickTime = currentTime;
        album_Image.classList.remove('rotation');
        pause_Btn.style.display = 'none';
        play_Btn.style.display = 'flex';
    });


    right_Btn.addEventListener('click', () => {
        audio_Btn.currentTime = audio_Btn.duration;
        audio_Btn.pause();
        album_Image.classList.remove('rotation');

    });

    right_Btn.addEventListener('click', () => {
        let currentTime = new Date().getTime();
        if (currentTime - lastClickTime < 300) {
            audio_Btn.pause();
            audio_Btn.currentTime = 0;
        } else {
            audio_Btn.play();
        }
        lastClickTime = currentTime;
        album_Image.classList.remove('rotation');
        pause_Btn.style.display = 'none';
        play_Btn.style.display = 'flex';
    });


});






