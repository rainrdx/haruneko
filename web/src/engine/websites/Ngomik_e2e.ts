import { TestFixture } from '../../../test/WebsitesFixture';

new TestFixture({
    plugin: {
        id: 'ngomik',
        title: 'Ngomik'
    },
    container: {
        url: 'https://ngomik.mom/manga/reborn-as-the-heavenly-demon/',
        id: '/manga/reborn-as-the-heavenly-demon/',
        title: 'Reborn as The Heavenly Demon'
    },
    child: {
        id: '/reborn-as-the-heavenly-demon-chapter-01/',
        title: 'Chapter 01'
    },
    entry: {
        index: 1,
        size: 168_025,
        type: 'image/jpeg'
    }
}).AssertWebsite();